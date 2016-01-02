using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using Owin.Security.Providers.VKontakte.Provider;

namespace Owin.Security.Providers.VKontakte
{
    public class VKontakteAuthenticationHandler : AuthenticationHandler<VKontakteAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private readonly ILogger logger;
        private readonly HttpClient httpClient;

        public VKontakteAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this.httpClient = httpClient;
            this.logger = logger;
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
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
                string baseUri = $"{Request.Scheme}{Uri.SchemeDelimiter}{Request.Host}{Request.PathBase}";

                string currentUri = $"{baseUri}{Request.Path}{Request.QueryString}";

                string redirectUri = $"{baseUri}{Options.CallbackPath}";

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                // comma separated
                string scope = string.Join(",", Options.Scope);

                string state = Options.StateDataFormat.Protect(properties);

                string authorizationEndpoint = $@"{Options.Endpoints.AuthorizationEndpoint}?client_id={Uri.EscapeDataString(Options.ClientId)}
                        &redirect_uri={Uri.EscapeDataString(redirectUri)}&scope={Uri.EscapeDataString(scope)}
                        &state={Uri.EscapeDataString(state)}&display={Uri.EscapeDataString(Options.Display)}";

                Response.Redirect(authorizationEndpoint);
            }

            return Task.FromResult<object>(null);
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string authorizationCode = GetParameterValueFromRequest("code");
                string state = GetParameterValueFromRequest("state");

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

                JObject response = await GetAuthorizationToken(authorizationCode);
                string accessToken = (string)response["access_token"];

                JObject user = await GetUser(response, accessToken);

                VKontakteAuthenticatedContext context = CreateAuthenticatedContext(user, accessToken, properties);

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        private string GetParameterValueFromRequest(string parameterName)
        {
            string value = null;
            IReadableStringCollection query = Request.Query;
            IList<string> values = query.GetValues(parameterName);
            if (values != null && values.Count == 1)
            {
                value = values[0];
            }
            return value;
        }

        private VKontakteAuthenticatedContext CreateAuthenticatedContext(JObject user, string accessToken,
            AuthenticationProperties properties)
        {
            var context = new VKontakteAuthenticatedContext(Context, user, accessToken)
            {
                Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType)
            };
            if (!string.IsNullOrEmpty(context.Id))
            {
                context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString,
                    Options.AuthenticationType));
            }
            if (!string.IsNullOrEmpty(context.UserName))
            {
                context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.UserName, XmlSchemaString,
                    Options.AuthenticationType));
            }

            context.Properties = properties;
            return context;
        }

        private async Task<JObject> GetUser(JObject response, string accessToken)
        {
            int userId = (int) response["user_id"];

            // Get the VK user
            var userRequestUri =
                new Uri(
                    $@"{Options.Endpoints.UserInfoEndpoint}?access_token={Uri.EscapeDataString(accessToken)}&user_id{userId}");
            HttpResponseMessage userResponse = await httpClient.GetAsync(userRequestUri, Request.CallCancelled);
            userResponse.EnsureSuccessStatusCode();

            var userReposnseAsString = await userResponse.Content.ReadAsStringAsync();
            var user = JObject.Parse(userReposnseAsString)["response"];
            return (JObject)user[0];
        }

        private async Task<JObject> GetAuthorizationToken(string authorizationCode)
        {
            string redirectUri = $"{Request.Scheme}://{Request.Host}{Request.PathBase}{Options.CallbackPath}";

            // Build up the body for the token request
            var body = new Dictionary<string, string>
            {
                {"code", authorizationCode},
                {"redirect_uri", redirectUri},
                {"client_id", Options.ClientId},
                {"client_secret", Options.ClientSecret}
            };

            // Request the token
            HttpResponseMessage tokenResponse =
                await httpClient.PostAsync(Options.Endpoints.TokenEndpoint, new FormUrlEncodedContent(body));
            tokenResponse.EnsureSuccessStatusCode();
            string tokenResponseAsString = await tokenResponse.Content.ReadAsStringAsync();

            // Deserializes the token response
            JObject response = JObject.Parse(tokenResponseAsString);
            return response;
        }
        
        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new VKontakteReturnEndpointContext(Context, ticket)
                {
                    SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                    RedirectUri = ticket.Properties.RedirectUri
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