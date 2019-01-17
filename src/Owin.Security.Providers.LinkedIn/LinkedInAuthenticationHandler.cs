using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.LinkedIn
{
    public class LinkedInAuthenticationHandler : AuthenticationHandler<LinkedInAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string TokenEndpoint = "https://www.linkedin.com/oauth/v2/accessToken";
        private const string UserInfoEndpoint = "https://api.linkedin.com/v2/me";
        private const string AuthorizationEndpoint = "https://www.linkedin.com/oauth/v2/authorization";
        private const string EmailEndpoint = "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public LinkedInAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                var state = GetQueryValue("state");
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

                var code = GetQueryValue("code");
                var accessTokenResponse = await GetAccessToken(code);
                dynamic response = JsonConvert.DeserializeObject<dynamic>(accessTokenResponse);
                var accessToken = (string)response.access_token;
                var expires = (string)response.expires_in;

                var userInfoResponse = await GetUserInfo(accessToken);
                var user = JObject.Parse(userInfoResponse);
                string email = null;
                if (Options.Scope.Contains(LinkedInAuthenticationOptions.EmailAddressScopeName))
                {
                    email = await GetUserEmail(accessToken);
                }

                var context = new LinkedInAuthenticatedContext(Context, user, accessToken, expires, email)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType)
                };

                AddClaimsToContextIdentity(context);

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
                this.GetHostName() +
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

            // comma separated
            var scope = string.Join(",", Options.Scope);

            // allow scopes to be specified via the authentication properties for this request, when specified they will already be comma separated
            if (properties.Dictionary.ContainsKey("scope"))
            {
                scope = properties.Dictionary["scope"];
            }
                
            var state = Options.StateDataFormat.Protect(properties);

            var authorizationEndpoint =
                AuthorizationEndpoint +
                "?response_type=code" +
                "&client_id=" + Uri.EscapeDataString(Options.ClientId) +
                "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                "&scope=" + Uri.EscapeDataString(scope) +
                "&state=" + Uri.EscapeDataString(state);


            var redirectContext = new LinkedInApplyRedirectContext(
                Context, Options,
                properties, authorizationEndpoint);
            Options.Provider.ApplyRedirect(redirectContext);

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

            var context = new LinkedInReturnEndpointContext(Context, ticket)
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

        /// <summary>
        ///     Gets proxy host name from <see cref="LinkedInAuthenticationOptions"/> if it is set.
        ///     If proxy host name is not set, gets application request host name.
        /// </summary>
        /// <returns>Host name.</returns>
        private string GetHostName()
        {
            return string.IsNullOrWhiteSpace(Options.ProxyHost) ? Request.Host.ToString() : Options.ProxyHost;
        }

        private static void SetAuthorizedRequestHeaders(string accessToken, HttpRequestMessage userRequest)
        {
            userRequest.Headers.Add("x-li-format", "json");
            userRequest.Headers.Add("Authorization", "Bearer " + accessToken);
        }

        private async Task<string> GetUserEmail(string accessToken)
        {
            var emailRequest = new HttpRequestMessage(HttpMethod.Get, EmailEndpoint);
            SetAuthorizedRequestHeaders(accessToken, emailRequest);
            var graphResponse = await _httpClient.SendAsync(emailRequest, Request.CallCancelled);
            try
            {
                graphResponse.EnsureSuccessStatusCode();
            }
            catch (Exception e)
            {
                _logger.WriteError(string.Format("Retrieving the user email using authorization from provider {0} failed. Message: {1}", Options.AuthenticationType, e.Message));
                throw;
            }

            var text = await graphResponse.Content.ReadAsStringAsync();
            var emailResponse = JObject.Parse(text);
            string email = null;
            var emailValue = emailResponse.SelectToken("elements[0].handle~.emailAddress");
            if (emailValue != null)
            {
                email = emailValue.Value<string>();
            }
            else
            {
                var errorMessageValue = emailResponse.SelectToken("elements[0].handle!.message");
                var errorMessage = string.Empty;
                if (errorMessageValue != null)
                {
                    errorMessage = errorMessageValue.Value<string>();
                }

                _logger.WriteWarning("Could not retrieve the user email from LinkedIn. Message: " + errorMessage);
            }

            return await Task.FromResult<string>(email);
        }

        private async Task<string> GetAccessToken(string code)
        {
            var requestPrefix = Request.Scheme + "://" + this.GetHostName();
            var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

            // Build up the body for the token request
            var body = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("redirect_uri", redirectUri),
                    new KeyValuePair<string, string>("client_id", Options.ClientId),
                    new KeyValuePair<string, string>("client_secret", Options.ClientSecret)
                };

            // Request the token
            var tokenResponse = await _httpClient.PostAsync(TokenEndpoint, new FormUrlEncodedContent(body));
            tokenResponse.EnsureSuccessStatusCode();
            return await tokenResponse.Content.ReadAsStringAsync();
        }

        private async Task<string> GetUserInfo(string accessToken)
        {
            var userInfoEndpoint = UserInfoEndpoint
                                          + "?projection=(" + string.Join(",", Options.ProfileFields.Distinct().ToArray()) + ")";
            var userRequest = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
            SetAuthorizedRequestHeaders(accessToken, userRequest);
            var graphResponse = await _httpClient.SendAsync(userRequest, Request.CallCancelled);
            graphResponse.EnsureSuccessStatusCode();
            return await graphResponse.Content.ReadAsStringAsync();
        }

        private void AddClaimsToContextIdentity(LinkedInAuthenticatedContext context)
        {
            if (!string.IsNullOrEmpty(context.Id))
            {
                context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType));
            }
            if (!string.IsNullOrEmpty(context.Email))
            {
                context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
            }
            if (!string.IsNullOrEmpty(context.GivenName))
            {
                context.Identity.AddClaim(new Claim(ClaimTypes.GivenName, context.GivenName, XmlSchemaString, Options.AuthenticationType));
            }
            if (!string.IsNullOrEmpty(context.FamilyName))
            {
                context.Identity.AddClaim(new Claim(ClaimTypes.Surname, context.FamilyName, XmlSchemaString, Options.AuthenticationType));
            }
            if (!string.IsNullOrEmpty(context.Name))
            {
                context.Identity.AddClaim(new Claim(ClaimTypes.Name, context.Name, XmlSchemaString, Options.AuthenticationType));
                context.Identity.AddClaim(new Claim("urn:linkedin:name", context.Name, XmlSchemaString, Options.AuthenticationType));
            }
            if (!string.IsNullOrEmpty(context.AccessToken))
            {
                context.Identity.AddClaim(new Claim("urn:linkedin:accesstoken", context.AccessToken, XmlSchemaString, Options.AuthenticationType));
            }
        }

        private string GetQueryValue(string name)
        {
            string result = null;
            var query = Request.Query;
            var values = query.GetValues(name);
            if (values != null && values.Count == 1)
            {
                result = values[0];
            }

            return result;
        }
    }
}