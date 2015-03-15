using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Owin.Security.Providers.SoundCloud.Provider;

namespace Owin.Security.Providers.SoundCloud
{
    public class SoundCloudAuthenticationHandler : AuthenticationHandler<SoundCloudAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string TokenEndpoint = "https://api.soundcloud.com/oauth2/token";
        private const string ConnectEndpoint = "https://soundcloud.com/connect";
        private const string UserInfoEndpoint = "https://api.soundcloud.com/me.json";
        private readonly HttpClient httpClient;
        private readonly ILogger logger;

        public SoundCloudAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this.httpClient = httpClient;
            this.logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;
            try
            {
                string code = null;
                string state = null;

                var query = Request.Query;
                var values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                if (!ValidateCorrelationId(properties, logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                var requestPrefix = Request.Scheme + "://" + Request.Host;
                var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                var body = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("redirect_uri", redirectUri),
                    new KeyValuePair<string, string>("client_id", Options.ClientId),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("client_secret", Options.ClientSecret)
                };

                var tokenResponse = await httpClient.PostAsync(TokenEndpoint, new FormUrlEncodedContent(body));
                tokenResponse.EnsureSuccessStatusCode();
                var text = await tokenResponse.Content.ReadAsStringAsync();

                dynamic response = JsonConvert.DeserializeObject<dynamic>(text);
                var accessToken = (string) response.access_token;

                var userRequest = new HttpRequestMessage(
                    HttpMethod.Get,
                    UserInfoEndpoint + "?oauth_token=" + Uri.EscapeDataString(accessToken));
                var userResponse = await httpClient.SendAsync(userRequest, Request.CallCancelled);
                userResponse.EnsureSuccessStatusCode();
                text = await userResponse.Content.ReadAsStringAsync();
                var user = JObject.Parse(text);

                var context = new SoundCloudAuthenticatedContext(Context, user, accessToken)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType)
                };
                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(
                        ClaimTypes.NameIdentifier, 
                        context.Id, 
                        XmlSchemaString,
                        Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.UserName))
                {
                    context.Identity.AddClaim(new Claim(
                        ClaimsIdentity.DefaultNameClaimType, 
                        context.UserName,
                        XmlSchemaString, 
                        Options.AuthenticationType));
                }
                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception exception)
            {
                logger.WriteError(exception.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                var baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                var currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                var redirectUri =
                    baseUri +
                    Options.CallbackPath;

                var properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                var state = Options.StateDataFormat.Protect(properties);

                var authorizationEndpoint =
                    ConnectEndpoint
                    + "?client_id=" + Uri.EscapeDataString(Options.ClientId)
                    + "&redirect_uri=" + Uri.EscapeDataString(redirectUri)
                    + "&response_type=" + "code"
                    + "&scope=" + "non-expiring"
                    + "&display=" + "popup"
                    + "&state=" + Uri.EscapeDataString(state);

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

                var ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new SoundCloudReturnEndpointContext(Context, ticket)
                {
                    SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                    RedirectUri = ticket.Properties.RedirectUri
                };

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null && context.Identity != null)
                {
                    var grantIdentity = context.Identity;
                    if (!string.Equals(
                        grantIdentity.AuthenticationType, 
                        context.SignInAsAuthenticationType, 
                        StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(
                            grantIdentity.Claims, 
                            context.SignInAsAuthenticationType, 
                            grantIdentity.NameClaimType, 
                            grantIdentity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    var redirectUri = context.RedirectUri;
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