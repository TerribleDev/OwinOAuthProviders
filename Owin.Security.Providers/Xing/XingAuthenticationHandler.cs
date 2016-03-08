using Microsoft.Owin;
using Microsoft.Owin.Helpers;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.Xing.Messages;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Owin.Security.Providers.Xing.Provider;

namespace Owin.Security.Providers.Xing
{
    internal class XingAuthenticationHandler : AuthenticationHandler<XingAuthenticationOptions>
    {
        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private const string StateCookie = "__XingState";
        private const string RequestTokenEndpoint = "https://api.xing.com/v1/request_token";
        private const string AuthenticationEndpoint = "https://api.xing.com/v1/authorize?oauth_token=";
        private const string AccessTokenEndpoint = "https://api.xing.com/v1/access_token";
        private const string UserInfoEndpoint = "https://api.xing.com/v1/users/me";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public XingAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        public override async Task<bool> InvokeAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                return await InvokeReturnPathAsync();
            }
            return false;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;
            try
            {
                var query = Request.Query;
                var protectedRequestToken = Request.Cookies[StateCookie];

                var requestToken = Options.StateDataFormat.Unprotect(protectedRequestToken);

                if (requestToken == null)
                {
                    _logger.WriteWarning("Invalid state");
                    return null;
                }

                properties = requestToken.Properties;

                var returnedToken = query.Get("oauth_token");
                if (string.IsNullOrWhiteSpace(returnedToken))
                {
                    _logger.WriteWarning("Missing oauth_token");
                    return new AuthenticationTicket(null, properties);
                }

                if (returnedToken != requestToken.Token)
                {
                    _logger.WriteWarning("Unmatched token");
                    return new AuthenticationTicket(null, properties);
                }

                var oauthVerifier = query.Get("oauth_verifier");
                if (string.IsNullOrWhiteSpace(oauthVerifier))
                {
                    _logger.WriteWarning("Missing or blank oauth_verifier");
                    return new AuthenticationTicket(null, properties);
                }

                var accessToken = await ObtainAccessTokenAsync(Options.ConsumerKey, Options.ConsumerSecret, requestToken, oauthVerifier);

                // Get the Xing user
                var users = await ObtainUserProfile(Options.ConsumerKey, Options.ConsumerSecret, accessToken);
                var context = new XingAuthenticatedContext(Context, accessToken.UserId, accessToken.Token, accessToken.TokenSecret, users)
                {
                    Identity = new ClaimsIdentity(Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType), Properties = requestToken.Properties
                };

                if (!string.IsNullOrEmpty(context.Id))
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, ClaimValueTypes.String, Options.AuthenticationType));
                if (!string.IsNullOrEmpty(context.Gender))
                    context.Identity.AddClaim(new Claim(ClaimTypes.Gender, context.Gender, ClaimValueTypes.String, Options.AuthenticationType));
                if (!string.IsNullOrEmpty(context.FirstName))
                    context.Identity.AddClaim(new Claim(ClaimTypes.GivenName, context.FirstName, ClaimValueTypes.String, Options.AuthenticationType));
                if (!string.IsNullOrEmpty(context.FirstName))
                    context.Identity.AddClaim(new Claim("urn:xing:lastname", context.LastName, ClaimValueTypes.String, Options.AuthenticationType));
                if (!string.IsNullOrEmpty(context.DisplayName))
                    context.Identity.AddClaim(new Claim(ClaimTypes.Name, context.DisplayName, ClaimValueTypes.String, Options.AuthenticationType));
                if (!string.IsNullOrEmpty(context.Email))
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, ClaimValueTypes.String, Options.AuthenticationType));
                if (!string.IsNullOrEmpty(context.Profile))
                    context.Identity.AddClaim(new Claim("urn:xing:profile", context.Profile, ClaimValueTypes.String, Options.AuthenticationType));
                if (context.BirthDate.HasValue)
                    context.Identity.AddClaim(new Claim(ClaimTypes.DateOfBirth, context.BirthDate.Value.ToShortDateString(), ClaimValueTypes.Date, Options.AuthenticationType));
                if (!string.IsNullOrEmpty(context.AccessToken))
                    context.Identity.AddClaim(new Claim("urn:xing:accesstoken", context.AccessToken, ClaimValueTypes.String, Options.AuthenticationType));

                Response.Cookies.Delete(StateCookie);

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }

        protected override async Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return;
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                var requestPrefix = Request.Scheme + "://" + Request.Host;
                var callBackUrl = requestPrefix + RequestPathBase + Options.CallbackPath;

                var extra = challenge.Properties;
                if (string.IsNullOrEmpty(extra.RedirectUri))
                {
                    extra.RedirectUri = requestPrefix + Request.PathBase + Request.Path + Request.QueryString;
                }

                var requestToken = await ObtainRequestTokenAsync(Options.ConsumerKey, Options.ConsumerSecret, callBackUrl, extra);

                if (requestToken.CallbackConfirmed)
                {
                    var xingAuthenticationEndpoint = AuthenticationEndpoint + requestToken.Token;

                    var cookieOptions = new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = Request.IsSecure
                    };

                    Response.Cookies.Append(StateCookie, Options.StateDataFormat.Protect(requestToken), cookieOptions);

                    var redirectContext = new XingApplyRedirectContext(
                        Context, Options,
                        extra, xingAuthenticationEndpoint);
                    Options.Provider.ApplyRedirect(redirectContext);
                }
                else
                {
                    _logger.WriteError("requestToken CallbackConfirmed!=true");
                }
            }
        }

        public async Task<bool> InvokeReturnPathAsync()
        {
            var model = await AuthenticateAsync();
            if (model == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new XingReturnEndpointContext(Context, model)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = model.Properties.RedirectUri
            };
            model.Properties.RedirectUri = null;

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null && context.Identity != null)
            {
                var signInIdentity = context.Identity;
                if (!string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, signInIdentity);
            }

            if (!context.IsRequestCompleted && context.RedirectUri != null)
            {
                if (context.Identity == null)
                {
                    // add a redirect hint that sign-in failed in some way
                    context.RedirectUri = WebUtilities.AddQueryString(context.RedirectUri, "error", "access_denied");
                }
                Response.Redirect(context.RedirectUri);
                context.RequestCompleted();
            }

            return context.IsRequestCompleted;
        }

        private async Task<RequestToken> ObtainRequestTokenAsync(string consumerKey, string consumerSecret, string callBackUri, AuthenticationProperties properties)
        {
            _logger.WriteVerbose("ObtainRequestToken");

            var nonce = Guid.NewGuid().ToString("N");

            var authorizationParts = new SortedDictionary<string, string>
            {
                { "oauth_callback", callBackUri },
                { "oauth_consumer_key", consumerKey },
                { "oauth_nonce", nonce },
                { "oauth_signature_method", "HMAC-SHA1" },
                { "oauth_timestamp", GenerateTimeStamp() },
                { "oauth_version", "1.0" }
            };

            var canonicalizedRequestBuilder = new StringBuilder();
            canonicalizedRequestBuilder.Append(HttpMethod.Post.Method);
            canonicalizedRequestBuilder.Append("&");
            canonicalizedRequestBuilder.Append(Uri.EscapeDataString(RequestTokenEndpoint));
            canonicalizedRequestBuilder.Append("&");
            canonicalizedRequestBuilder.Append(Uri.EscapeDataString(GetParameters(authorizationParts)));

            var signature = ComputeSignature(consumerSecret, null, canonicalizedRequestBuilder.ToString());
            authorizationParts.Add("oauth_signature", signature);

            var authorizationHeaderBuilder = new StringBuilder();
            authorizationHeaderBuilder.Append("OAuth ");
            foreach (var authorizationPart in authorizationParts)
            {
                authorizationHeaderBuilder.AppendFormat("{0}=\"{1}\", ", authorizationPart.Key, Uri.EscapeDataString(authorizationPart.Value));
            }
            authorizationHeaderBuilder.Length = authorizationHeaderBuilder.Length - 2;

            var request = new HttpRequestMessage(HttpMethod.Post, RequestTokenEndpoint);
            request.Headers.Add("Authorization", authorizationHeaderBuilder.ToString());

            var response = await _httpClient.SendAsync(request, Request.CallCancelled);
            response.EnsureSuccessStatusCode();
            var responseText = await response.Content.ReadAsStringAsync();

            var responseParameters = WebHelpers.ParseForm(responseText);
            if (string.Equals(responseParameters["oauth_callback_confirmed"], "true", StringComparison.InvariantCulture))
            {
                return new RequestToken { Token = Uri.UnescapeDataString(responseParameters["oauth_token"]), TokenSecret = Uri.UnescapeDataString(responseParameters["oauth_token_secret"]), CallbackConfirmed = true, Properties = properties };
            }

            return new RequestToken();
        }

        private async Task<AccessToken> ObtainAccessTokenAsync(string consumerKey, string consumerSecret, RequestToken token, string verifier)
        {
            //https://dev.xing.com/docs/authentication

            _logger.WriteVerbose("ObtainAccessToken");

            var nonce = Guid.NewGuid().ToString("N");

            var authorizationParts = new SortedDictionary<string, string>
            {
                { "oauth_consumer_key", consumerKey },
                { "oauth_nonce", nonce },
                { "oauth_signature_method", "HMAC-SHA1" },
                { "oauth_token", token.Token },
                { "oauth_timestamp", GenerateTimeStamp() },
                { "oauth_verifier", verifier },
                { "oauth_version", "1.0" },
            };

            var parameterBuilder = new StringBuilder();
            foreach (var authorizationKey in authorizationParts)
            {
                parameterBuilder.AppendFormat("{0}={1}&", Uri.EscapeDataString(authorizationKey.Key), Uri.EscapeDataString(authorizationKey.Value));
            }
            parameterBuilder.Length--;
            var parameterString = parameterBuilder.ToString();

            var canonicalizedRequestBuilder = new StringBuilder();
            canonicalizedRequestBuilder.Append(HttpMethod.Post.Method);
            canonicalizedRequestBuilder.Append("&");
            canonicalizedRequestBuilder.Append(Uri.EscapeDataString(AccessTokenEndpoint));
            canonicalizedRequestBuilder.Append("&");
            canonicalizedRequestBuilder.Append(Uri.EscapeDataString(parameterString));

            var signature = ComputeSignature(consumerSecret, token.TokenSecret, canonicalizedRequestBuilder.ToString());
            authorizationParts.Add("oauth_signature", signature);
            authorizationParts.Remove("oauth_verifier");

            var authorizationHeaderBuilder = new StringBuilder();
            authorizationHeaderBuilder.Append("OAuth ");
            foreach (var authorizationPart in authorizationParts)
            {
                authorizationHeaderBuilder.AppendFormat(
                    "{0}=\"{1}\", ", authorizationPart.Key, Uri.EscapeDataString(authorizationPart.Value));
            }
            authorizationHeaderBuilder.Length = authorizationHeaderBuilder.Length - 2;

            var request = new HttpRequestMessage(HttpMethod.Post, AccessTokenEndpoint);
            request.Headers.Add("Authorization", authorizationHeaderBuilder.ToString());

            var formPairs = new List<KeyValuePair<string, string>>()
            {
                new KeyValuePair<string, string>("oauth_verifier", verifier)
            };

            request.Content = new FormUrlEncodedContent(formPairs);

            var response = await _httpClient.SendAsync(request, Request.CallCancelled);

            if (!response.IsSuccessStatusCode)
            {
                _logger.WriteError("AccessToken request failed with a status code of " + response.StatusCode);
                response.EnsureSuccessStatusCode(); // throw
            }

            var responseText = await response.Content.ReadAsStringAsync();

            var responseParameters = WebHelpers.ParseForm(responseText);

            return new AccessToken
            {
                Token = Uri.UnescapeDataString(responseParameters["oauth_token"]),
                TokenSecret = Uri.UnescapeDataString(responseParameters["oauth_token_secret"]),
                UserId = Uri.UnescapeDataString(responseParameters["user_id"]),
            };
        }

        private async Task<JObject> ObtainUserProfile(string consumerKey, string consumerSecret, AccessToken token)
        {
            _logger.WriteVerbose("ObtainUserProfile");

            var queryParts = new Dictionary<string, string>
            {
                {"fields", ""}
            };

            var nonce = Guid.NewGuid().ToString("N");

            var authorizationParts = new SortedDictionary<string, string>
            {
                { "oauth_consumer_key", consumerKey },
                { "oauth_nonce", nonce },
                { "oauth_signature_method", "HMAC-SHA1" },
                { "oauth_token", token.Token },
                { "oauth_timestamp", GenerateTimeStamp() },
                { "oauth_version", "1.0" },
            };

            var parameterBuilder = new StringBuilder();
            foreach (var authorizationKey in authorizationParts.Union(queryParts).OrderBy(x => x.Key))
            {
                parameterBuilder.AppendFormat("{0}={1}&", Uri.EscapeDataString(authorizationKey.Key), Uri.EscapeDataString(authorizationKey.Value));
            }
            parameterBuilder.Length--;
            var parameterString = parameterBuilder.ToString();

            var canonicalizedRequestBuilder = new StringBuilder();
            canonicalizedRequestBuilder.Append(HttpMethod.Get.Method);
            canonicalizedRequestBuilder.Append("&");
            canonicalizedRequestBuilder.Append(Uri.EscapeDataString(UserInfoEndpoint));
            canonicalizedRequestBuilder.Append("&");
            canonicalizedRequestBuilder.Append(Uri.EscapeDataString(parameterString));

            string signature = ComputeSignature(consumerSecret, token.TokenSecret, canonicalizedRequestBuilder.ToString());
            authorizationParts.Add("oauth_signature", signature);

            var authorizationHeaderBuilder = new StringBuilder();
            authorizationHeaderBuilder.Append("OAuth ");
            foreach (var authorizationPart in authorizationParts)
            {
                authorizationHeaderBuilder.AppendFormat("{0}=\"{1}\", ", authorizationPart.Key, Uri.EscapeDataString(authorizationPart.Value));
            }
            authorizationHeaderBuilder.Length = authorizationHeaderBuilder.Length - 2;

            var requestUrl = WebUtilities.AddQueryString(UserInfoEndpoint, queryParts);
            var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
            request.Headers.Add("Authorization", authorizationHeaderBuilder.ToString());

            var response = await _httpClient.SendAsync(request, Request.CallCancelled);

            if (!response.IsSuccessStatusCode)
            {
                _logger.WriteError("AccessToken request failed with a status code of " + response.StatusCode);
                response.EnsureSuccessStatusCode(); // throw
            }

            var responseText = await response.Content.ReadAsStringAsync();
            return JObject.Parse(responseText);
        }

        private static string GetParameters(SortedDictionary<string, string> parameters)
        {
            var parameterBuilder = new StringBuilder();
            foreach (var param in parameters)
            {
                parameterBuilder.AppendFormat("{0}={1}&", Uri.EscapeDataString(param.Key), Uri.EscapeDataString(param.Value));
            }
            parameterBuilder.Length--;
            return parameterBuilder.ToString();
        }

        private static string GenerateTimeStamp()
        {
            var secondsSinceUnixEpocStart = DateTime.UtcNow - Epoch;
            return Convert.ToInt64(secondsSinceUnixEpocStart.TotalSeconds).ToString(CultureInfo.InvariantCulture);
        }
        
        private static string ComputeSignature(string consumerSecret, string tokenSecret, string signatureData)
        {
            using (var algorithm = new HMACSHA1())
            {
                algorithm.Key = Encoding.ASCII.GetBytes(string.Format(CultureInfo.InvariantCulture, "{0}&{1}", Uri.EscapeDataString(consumerSecret), string.IsNullOrEmpty(tokenSecret) ? string.Empty : Uri.EscapeDataString(tokenSecret)));
                var hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(signatureData));
                return Convert.ToBase64String(hash);
            }
        }
    }
}