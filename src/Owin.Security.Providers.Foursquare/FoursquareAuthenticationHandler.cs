using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using Owin.Security.Providers.Foursquare.Provider;

namespace Owin.Security.Providers.Foursquare
{
    public class FoursquareAuthenticationHandler : AuthenticationHandler<FoursquareAuthenticationOptions>
    {
        private const string AuthorizationEndpoint = "https://foursquare.com/oauth2/authenticate";
        private const string TokenEndpoint = "https://foursquare.com/oauth2/access_token";
        private const string GraphApiEndpoint = "https://api.foursquare.com/v2/users/self";
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private static readonly DateTime VersionDate = new DateTime(2015, 3, 19);

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public FoursquareAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        public override async Task<bool> InvokeAsync()
        {
            if ((string.IsNullOrEmpty(Options.CallbackPath) == false) && (Options.CallbackPath == Request.Path.ToString()))
            {
                return await InvokeReturnPathAsync();
            }

            return false;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            _logger.WriteVerbose("AuthenticateCore");

            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                var query = Request.Query;
                var values = query.GetValues("code");

                if ((values != null) && (values.Count == 1))
                {
                    code = values[0];
                }

                values = query.GetValues("state");

                if ((values != null) && (values.Count == 1))
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);

                if (properties == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (ValidateCorrelationId(properties, _logger) == false)
                {
                    return new AuthenticationTicket(null, properties);
                }

                var tokenRequestParameters = new List<KeyValuePair<string, string>>()
				{
					new KeyValuePair<string, string>("client_id", Options.ClientId),
					new KeyValuePair<string, string>("client_secret", Options.ClientSecret),
					new KeyValuePair<string, string>("grant_type", "authorization_code"),
					new KeyValuePair<string, string>("redirect_uri", GenerateRedirectUri()),
					new KeyValuePair<string, string>("code", code),
				};

                var requestContent = new FormUrlEncodedContent(tokenRequestParameters);

                var response = await _httpClient.PostAsync(TokenEndpoint, requestContent, Request.CallCancelled);
                response.EnsureSuccessStatusCode();

                var oauthTokenResponse = await response.Content.ReadAsStringAsync();

                var oauth2Token = JObject.Parse(oauthTokenResponse);
                var accessToken = oauth2Token["access_token"].Value<string>();

                if (string.IsNullOrWhiteSpace(accessToken))
                {
                    _logger.WriteWarning("Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }

                // ReSharper disable once StringLiteralTypo
                var graphResponse = await _httpClient.GetAsync(GraphApiEndpoint + "?oauth_token=" + Uri.EscapeDataString(accessToken) + "&m=foursquare&v=" + VersionDate.ToString("yyyyyMMdd"), Request.CallCancelled);
                graphResponse.EnsureSuccessStatusCode();

                var accountstring = await graphResponse.Content.ReadAsStringAsync();
                var accountInformation = JObject.Parse(accountstring);
                var user = (JObject)accountInformation["response"]["user"];

                var context = new FoursquareAuthenticatedContext(Context, user, accessToken);

                context.Identity = new ClaimsIdentity(
                    new[]
					{
						new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType),
						new Claim(ClaimTypes.Name, context.Name, XmlSchemaString, Options.AuthenticationType),
						new Claim("urn:foursquare:id", context.Id, XmlSchemaString, Options.AuthenticationType),
						new Claim("urn:foursquare:name", context.Name, XmlSchemaString, Options.AuthenticationType),
					},
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                if (string.IsNullOrWhiteSpace(context.Email) == false)
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
                }

                if (string.IsNullOrWhiteSpace(context.Twitter) == false)
                {
                    context.Identity.AddClaim(new Claim("urn:foursquare:twitter", context.Twitter, XmlSchemaString, Options.AuthenticationType));
                }

                await Options.Provider.Authenticated(context);

                context.Properties = properties;

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteWarning("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            _logger.WriteVerbose("ApplyResponseChallenge");

            if (Response.StatusCode != (int)HttpStatusCode.Unauthorized)
            {
                return Task.FromResult<object>(null);
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge == null) return Task.FromResult<object>(null);
            var baseUri = Request.Scheme + Uri.SchemeDelimiter + Request.Host + Request.PathBase;
            var currentUri = baseUri + Request.Path + Request.QueryString;
            var redirectUri = baseUri + Options.CallbackPath;

            var extra = challenge.Properties;

            if (string.IsNullOrEmpty(extra.RedirectUri))
            {
                extra.RedirectUri = currentUri;
            }

            // OAuth2 10.12 CSRF
            GenerateCorrelationId(extra);

            var state = Options.StateDataFormat.Protect(extra);

            var authorizationEndpoint = AuthorizationEndpoint +
                                        "?client_id=" + Uri.EscapeDataString(Options.ClientId) +
                                        "&response_type=code" +
                                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                                        "&state=" + Uri.EscapeDataString(state);

            Response.Redirect(authorizationEndpoint);

            return Task.FromResult<object>(null);
        }

        public async Task<bool> InvokeReturnPathAsync()
        {
            _logger.WriteVerbose("InvokeReturnPath");

            var model = await AuthenticateAsync();

            var context = new FoursquareReturnEndpointContext(Context, model)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = model.Properties.RedirectUri
            };

            model.Properties.RedirectUri = null;

            await Options.Provider.ReturnEndpoint(context);

            if ((context.SignInAsAuthenticationType != null) && (context.Identity != null))
            {
                var signInIdentity = context.Identity;

                if (string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal) == false)
                {
                    signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
                }

                Context.Authentication.SignIn(context.Properties, signInIdentity);
            }

            if (context.IsRequestCompleted || (context.RedirectUri == null))
                return context.IsRequestCompleted;
            if (context.Identity == null)
            {
                context.RedirectUri = WebUtilities.AddQueryString(context.RedirectUri, "error", "access_denied");
            }

            Response.Redirect(context.RedirectUri);

            context.RequestCompleted();

            return context.IsRequestCompleted;
        }

        private string GenerateRedirectUri()
        {
            var requestPrefix = Request.Scheme + "://" + Request.Host;
            var redirectUri = requestPrefix + RequestPathBase + Options.CallbackPath;
            return redirectUri;
        }
    }
}