using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Owin.Security.Providers.Orcid.Message;

namespace Owin.Security.Providers.Orcid
{
    public class OrcidAuthenticationHandler : AuthenticationHandler<OrcidAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private readonly ILogger logger;
        private readonly HttpClient httpClient;

        public OrcidAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this.httpClient = httpClient;
            this.logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = new AuthenticationProperties();

            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                if (state != null)
                {
                    properties = Options.StateDataFormat.Unprotect(state);
                    if (properties == null)
                    {
                        return null;
                    }

                    // OAuth2 10.12 CSRF
                    if (!ValidateCorrelationId(properties, logger))
                    {
                        return new AuthenticationTicket(null, properties);
                    }
                }

                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                // Build up the body for the token request
                var body = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("client_id", Options.ClientId),
                    new KeyValuePair<string, string>("client_secret", Options.ClientSecret),
                    new KeyValuePair<string, string>("scope", "/read-public"),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("redirect_uri", redirectUri),
                };

                // Request the token
                var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.Endpoints.TokenEndpoint);
                requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                requestMessage.Content = new FormUrlEncodedContent(body);

                HttpResponseMessage tokenResponse = await httpClient.SendAsync(requestMessage);
                tokenResponse.EnsureSuccessStatusCode();
                string text = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the token response
                dynamic response = JsonConvert.DeserializeObject<dynamic>(text);
                string accessToken = (string)response.access_token;
                string refreshToken = (string)response.refresh_token;
                string orcid = (string)response.orcid;

                string profileEndpoint =
                    string.Format("{0}/{1}/{2}", 
                    Options.Endpoints.ApiEndpoint,
                    orcid,
                    "orcid-profile/");

                // Get Orcid profile
                HttpRequestMessage userRequest = new HttpRequestMessage(HttpMethod.Get, profileEndpoint);
                
                //Requesting public info for now - no authirization needed
                //userRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                userRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                HttpResponseMessage userResponse = await httpClient.SendAsync(userRequest, Request.CallCancelled);
                userResponse.EnsureSuccessStatusCode();
                text = await userResponse.Content.ReadAsStringAsync();

                /*
                This command works in curl but not here
                curl -H "Content-Type: application/orcid+xml" -H "Authorization: Bearer 8394381e-fa2e-4cf3-8bb5-3f4afcab00dc" "http://pub.orcid.org/v1.2/0000-0002-0113-3978/orcid-profile/"
                */

                // Get the Orcid user using the user info endpoint, which is part of the token - response.id

				var context = text.ToAuthenticationContext(Context, orcid, accessToken);

                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.UserName))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.UserName, XmlSchemaString, Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.FirstName))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.GivenName, context.FirstName, XmlSchemaString, Options.AuthenticationType));
                }

                if (!string.IsNullOrEmpty(context.LastName))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Surname, context.LastName, XmlSchemaString, Options.AuthenticationType));
                }

                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                string redirectUri =
                    baseUri +
                    Options.CallbackPath;

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                string state = Options.StateDataFormat.Protect(properties);

                string authorizationEndpoint = string.Format(
                    "{0}?client_id={1}&response_type={2}&scope={3}&redirect_uri={4}",
                    Options.Endpoints.AuthorizationEndpoint,
                    Options.ClientId,
                    "code",
                    @"/authenticate",
                    HttpUtility.UrlEncode(redirectUri)
                    );

                //RZ: Need this?
                if (Options.Prompt != null)
                {
                    authorizationEndpoint += string.Format("&prompt={0}", Options.Prompt);
                }

                Response.Redirect(authorizationEndpoint);
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                // TODO: error responses

                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new OrcidReturnEndpointContext(Context, ticket)
                {
                    SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                    RedirectUri = "/Account/ExternalLoginCallback" //ticket.Properties.RedirectUri
                };

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null &&
                    context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }
            return false;
        }
    }
}
