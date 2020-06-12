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
using Owin.Security.Providers.EDevlet.Provider;

namespace Owin.Security.Providers.EDevlet
{
    public class EDevletAuthenticationHandler : AuthenticationHandler<EDevletAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string TokenEndpoint = "https://giris.turkiye.gov.tr/OAuth2AuthorizationServer/AccessTokenController";
        private const string AuthenticationEndpoint = "https://giris.turkiye.gov.tr/OAuth2AuthorizationServer/AuthenticationController";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public EDevletAuthenticationHandler(HttpClient httpClient, ILogger logger)
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

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                var requestPrefix = Uri.UriSchemeHttps + Uri.SchemeDelimiter + Request.Host;
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
                var tokenResponse =
                    await _httpClient.PostAsync(TokenEndpoint, new FormUrlEncodedContent(body));
                tokenResponse.EnsureSuccessStatusCode();
                var text = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the token response
                dynamic response = JsonConvert.DeserializeObject<dynamic>(text);
                var accessToken = (string)response.access_token;
                if (String.IsNullOrWhiteSpace(accessToken))
                {

                    var error = (string)response.error;
                    var error_description = (string)response.error_description;
                    throw new ApplicationException($"{error}:{error_description}");
                }


                string refreshToken = null;
                if (response.refresh_token != null)
                    refreshToken = (string)response.refresh_token;

                string authText = await EDevletAuthenticate(accessToken, "Ad-Soyad");

                dynamic authResponseJson = JsonConvert.DeserializeObject<dynamic>(authText);
                var resultCode = (string)authResponseJson.sonucKodu;
                if (resultCode != "EDV09.000")
                {
                    var resultDesc = (string)authResponseJson.sonucAciklamasi;
                    throw new ApplicationException($"{resultCode}:{resultDesc}");

                }
                var identityNo = (string)authResponseJson.kullaniciBilgileri.kimlikNo;
                var name = (string)authResponseJson.kullaniciBilgileri.ad;
                var surname = (string)authResponseJson.kullaniciBilgileri.soyad;

                var context = new EDevletAuthenticatedContext(Context, identityNo, name, surname, accessToken)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType)
                };


                if (!string.IsNullOrEmpty(context.IdentityNo))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.IdentityNo, XmlSchemaString, Options.AuthenticationType));
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.FullName, XmlSchemaString, Options.AuthenticationType));
                    context.Identity.AddClaim(new Claim(EDevletConstants.IdentityNoClaimType, context.IdentityNo, Options.AuthenticationType));
                }



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

        private async Task<string> EDevletAuthenticate(string accessToken, string kapsam)
        {
            var kimlikDogrulaBody = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("clientId", Options.ClientId),
                    new KeyValuePair<string, string>("accessToken", accessToken),
                    new KeyValuePair<string, string>("resourceId", "1"),
                    new KeyValuePair<string, string>("kapsam",kapsam),
                };

            var kimlikResponse =
                await _httpClient.PostAsync(AuthenticationEndpoint, new FormUrlEncodedContent(kimlikDogrulaBody));
            kimlikResponse.EnsureSuccessStatusCode();
            var kimlikText = await kimlikResponse.Content.ReadAsStringAsync();
            return kimlikText;
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
                Uri.UriSchemeHttps +
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

            // comma separated
            var scope = string.Join(";", Options.Scope);

            var state = Options.StateDataFormat.Protect(properties);

            var authorizationEndpoint =
                "https://giris.turkiye.gov.tr/OAuth2AuthorizationServer/AuthorizationController" +
                "?response_type=code" +
                "&client_id=" + Uri.EscapeDataString(Options.ClientId) +
                "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                "&scope=" + Uri.EscapeDataString(scope) +
                "&state=" + Uri.EscapeDataString(state);


            Response.Redirect(authorizationEndpoint);

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (!Options.CallbackPath.HasValue || Options.CallbackPath != Request.Path)
                return false;


            var ticket = await AuthenticateAsync();
            if (ticket == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new EDevletReturnEndpointContext(Context, ticket)
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