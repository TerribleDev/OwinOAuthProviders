using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Untappd
{
    public class UntappdAuthenticationHandler : AuthenticationHandler<UntappdAuthenticationOptions>
    {
        private const string StateCookie = "_StateCookie";
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public UntappdAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;

                var query = Request.Query;
                var values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = string.Copy(values.First());
                }

                // restore State from Cookie
                var state = Request.Cookies[StateCookie];
                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                var requestPrefix = Request.Scheme + "://" + Request.Host;
                var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                //// Build up the body for the token request
                //var body = new List<KeyValuePair<string, string>>();
                //body.Add(new KeyValuePair<string, string>("client_id", Options.ClientId));
                //body.Add(new KeyValuePair<string, string>("client_secret", Options.ClientSecret));
                //body.Add(new KeyValuePair<string, string>("redirect_url", redirectUri));
                //body.Add(new KeyValuePair<string, string>("response_type", "code"));
                //body.Add(new KeyValuePair<string, string>("code", code));

                // Request the token
                var requestMessage = new HttpRequestMessage(HttpMethod.Get,
                    $@"{Options.Endpoints.TokenEndpoint}/?client_id={Options.ClientId}&client_secret={Options
                        .ClientSecret}&response_type=code&redirect_url={redirectUri}&code={code}");
                requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                var tokenResponse = await _httpClient.SendAsync(requestMessage);
                tokenResponse.EnsureSuccessStatusCode();
                var text = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the token response
                var response = JsonConvert.DeserializeObject<ResponseRoot>(text);
                var accessToken = response.Response.AccessToken;

                // Get the Untappd user
                var userRequest = new HttpRequestMessage(HttpMethod.Get, Options.Endpoints.UserInfoEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken));
                userRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                var userResponse = await _httpClient.SendAsync(userRequest, Request.CallCancelled);
                userResponse.EnsureSuccessStatusCode();
                text = await userResponse.Content.ReadAsStringAsync();
                var user = JObject.Parse(text);

                var context = new UntappdAuthenticatedContext(Context, user, accessToken)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType)
                };

                // Add access_token to Claims to be used later on authenticated Untappd API requests
                context.Identity.AddClaim(new Claim("UntappdAccessToken", accessToken));

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
                if (!string.IsNullOrEmpty(context.Name))
                {
                    context.Identity.AddClaim(new Claim("urn:Untappd:name", context.Name, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Link))
                {
                    context.Identity.AddClaim(new Claim("urn:Untappd:url", context.Link, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.AvatarUrl))
                {
                    context.Identity.AddClaim(new Claim("urn:Untappd:avatar", context.AvatarUrl, XmlSchemaString, Options.AuthenticationType));
                }

                //IDictionary<string, string> data = new Dictionary<string, string>
                //     {
                //        { "userData", "Data" }
                //    };
                //properties = new AuthenticationProperties(data);

                context.Properties = properties;
                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
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

            if (challenge == null) return Task.FromResult<object>(null);
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

            var authorizationEndpoint =
                Options.Endpoints.AuthorizationEndpoint +
                "?client_id=" + Uri.EscapeDataString(Options.ClientId) +
                "&redirect_url=" + Uri.EscapeDataString(redirectUri) +
                "&response_type=" + "code";

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = Request.IsSecure
            };

            Response.Cookies.Append(StateCookie, Options.StateDataFormat.Protect(properties), cookieOptions);
            Response.Redirect(authorizationEndpoint);

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (!Options.CallbackPath.HasValue || Options.CallbackPath != Request.Path) return false;
            // TODO: error responses

            var ticket = await AuthenticateAsync();
            if (ticket == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new UntappdReturnEndpointContext(Context, ticket)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = ticket.Properties.RedirectUri
            };

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null &&
                context.Identity != null)
            {
                var grantIdentity = context.Identity;
                if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, grantIdentity);
            }

            if (context.IsRequestCompleted || context.RedirectUri == null) return context.IsRequestCompleted;
            var redirectUri = context.RedirectUri;
            if (context.Identity == null)
            {
                // add a redirect hint that sign-in failed in some way
                redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
            }
            Response.Redirect(redirectUri);
            context.RequestCompleted();

            return context.IsRequestCompleted;
        }
    }
}