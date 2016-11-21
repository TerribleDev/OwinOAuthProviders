using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
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

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public VKontakteAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
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

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge == null) return Task.FromResult<object>(null);
            var baseUri = $"{Request.Scheme}{Uri.SchemeDelimiter}{Request.Host}{Request.PathBase}";

            var currentUri = $"{baseUri}{Request.Path}{Request.QueryString}";

            var redirectUri = $"{baseUri}{Options.CallbackPath}";

            var properties = challenge.Properties;
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = currentUri;
            }

            // OAuth2 10.12 CSRF
            GenerateCorrelationId(properties);

            // comma separated
            var scope = string.Join(",", Options.Scope);

            var state = Options.StateDataFormat.Protect(properties);

            var authorizationEndpoint =
                $"{Options.Endpoints.AuthorizationEndpoint}?client_id={Uri.EscapeDataString(Options.ClientId)}&redirect_uri={Uri.EscapeDataString(redirectUri)}&scope={Uri.EscapeDataString(scope)}&state={Uri.EscapeDataString(state)}&display={Uri.EscapeDataString(Options.Display)}";

            Response.Redirect(authorizationEndpoint);

            return Task.FromResult<object>(null);
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                var authorizationCode = GetParameterValueFromRequest("code");
                var state = GetParameterValueFromRequest("state");

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

                var response = await GetAuthorizationToken(authorizationCode);
                var accessToken = (string)response["access_token"];

                var user = await GetUser(response, accessToken);

                var context = CreateAuthenticatedContext(user, accessToken, properties);
                var email = response["email"]?.ToString();
                if(!string.IsNullOrWhiteSpace(email))
                {
                    // Email support. VK send it with access_token
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, email, XmlSchemaString, Options.AuthenticationType));
                }

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        private string GetParameterValueFromRequest(string parameterName)
        {
            string value = null;
            var query = Request.Query;
            var values = query.GetValues(parameterName);
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
            var userId = (int)response["user_id"];

            // Get the VK user
            var userRequestUri = new Uri(
                $"{Options.Endpoints.UserInfoEndpoint}?access_token={Uri.EscapeDataString(accessToken)}&user_id{userId}");
            var userResponse = await _httpClient.GetAsync(userRequestUri, Request.CallCancelled);
            userResponse.EnsureSuccessStatusCode();

            var userResponseAsString = await userResponse.Content.ReadAsStringAsync();
            var user = JObject.Parse(userResponseAsString)["response"];
            return (JObject)user[0];
        }

        private async Task<JObject> GetAuthorizationToken(string authorizationCode)
        {
            var redirectUri = $"{Request.Scheme}://{Request.Host}{Request.PathBase}{Options.CallbackPath}";

            // Build up the body for the token request
            var body = new Dictionary<string, string>
            {
                {"code", authorizationCode},
                {"redirect_uri", redirectUri},
                {"client_id", Options.ClientId},
                {"client_secret", Options.ClientSecret}
            };

            // Request the token
            var tokenResponse =
                await _httpClient.PostAsync(Options.Endpoints.TokenEndpoint, new FormUrlEncodedContent(body));
            tokenResponse.EnsureSuccessStatusCode();
            var tokenResponseAsString = await tokenResponse.Content.ReadAsStringAsync();

            // Deserializes the token response
            var response = JObject.Parse(tokenResponseAsString);
            return response;
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (!Options.CallbackPath.HasValue || Options.CallbackPath != Request.Path) return false;
            var ticket = await AuthenticateAsync();
            if (ticket == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
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
