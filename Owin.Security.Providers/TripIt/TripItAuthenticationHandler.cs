// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Helpers;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using Owin.Security.Providers.TripIt.Messages;
using Owin.Security.Providers.TripIt.Provider;

namespace Owin.Security.Providers.TripIt
{
    internal class TripItAuthenticationHandler : AuthenticationHandler<TripItAuthenticationOptions>
    {
        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private const string StateCookie = "__TripItState";
        private const string RequestTokenEndpoint = "https://api.tripit.com/oauth/request_token";
        private const string AuthenticationEndpoint = "https://www.tripit.com/oauth/authorize";
        private const string AccessTokenEndpoint = "https://api.tripit.com/oauth/access_token";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public TripItAuthenticationHandler(HttpClient httpClient, ILogger logger)
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
                IReadableStringCollection query = Request.Query;
                string protectedRequestToken = Request.Cookies[StateCookie];

                RequestToken requestToken = Options.StateDataFormat.Unprotect(protectedRequestToken);

                if (requestToken == null)
                {
                    _logger.WriteWarning("Invalid state");
                    return null;
                }

                properties = requestToken.Properties;

                string returnedToken = query.Get("oauth_token");
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

                AccessToken accessToken = await ObtainAccessTokenAsync(Options.ConsumerKey, Options.ConsumerSecret, requestToken);

                JObject profileObject = await ObtainUserProfile(Options.ConsumerKey, Options.ConsumerSecret, accessToken);

                var context = new TripItAuthenticatedContext(Context, profileObject, accessToken.Token, accessToken.TokenSecret);

                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);
                if (!String.IsNullOrEmpty(context.ScreenName))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.ScreenName,
                        "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType));
                }
                if (!String.IsNullOrEmpty(context.DisplayName))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Name, context.DisplayName,
                        "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType));
                }
                if (!String.IsNullOrEmpty(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email,
                        "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType));
                }
                if (!String.IsNullOrEmpty(context.UserId))
                {
                    context.Identity.AddClaim(new Claim("urn:tripit:userid", context.UserId,
                        "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType));
                }
                if (!String.IsNullOrEmpty(context.ScreenName))
                {
                    context.Identity.AddClaim(new Claim("urn:tripit:sreenname", context.ScreenName,
                        "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType));
                }
                context.Properties = requestToken.Properties;

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

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2202:Do not dispose objects multiple times", Justification = "MemoryStream.Dispose is idempotent")]
        protected override async Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return;
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string callBackUrl = requestPrefix + RequestPathBase + Options.CallbackPath;

                AuthenticationProperties extra = challenge.Properties;
                if (string.IsNullOrEmpty(extra.RedirectUri))
                {
                    extra.RedirectUri = requestPrefix + Request.PathBase + Request.Path + Request.QueryString;
                }

                RequestToken requestToken = await ObtainRequestTokenAsync(Options.ConsumerKey, Options.ConsumerSecret, extra);

                if (requestToken.CallbackConfirmed)
                {
                    string authenticationEndpoint = AuthenticationEndpoint + "?oauth_token=" + requestToken.Token
                                                         + "&oauth_callback=" + Uri.EscapeDataString(callBackUrl);

                    var cookieOptions = new CookieOptions
                    {
                        HttpOnly = true,
                        Secure = Request.IsSecure
                    };

                    Response.StatusCode = 302;
                    Response.Cookies.Append(StateCookie, Options.StateDataFormat.Protect(requestToken), cookieOptions);
                    Response.Headers.Set("Location", authenticationEndpoint);
                }
                else
                {
                    _logger.WriteError("requestToken CallbackConfirmed!=true");
                }
            }
        }

        public async Task<bool> InvokeReturnPathAsync()
        {
            AuthenticationTicket model = await AuthenticateAsync();
            if (model == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new TripItReturnEndpointContext(Context, model)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = model.Properties.RedirectUri
            };
            model.Properties.RedirectUri = null;

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null && context.Identity != null)
            {
                ClaimsIdentity signInIdentity = context.Identity;
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

        private async Task<RequestToken> ObtainRequestTokenAsync(string consumerKey, string consumerSecret, AuthenticationProperties properties)
        {
            _logger.WriteVerbose("ObtainRequestToken");

            string nonce = Guid.NewGuid().ToString("N");

            var authorizationParts = new SortedDictionary<string, string>
            {
                { "oauth_consumer_key", consumerKey },
                { "oauth_nonce", nonce },
                { "oauth_signature_method", "HMAC-SHA1" },
                { "oauth_timestamp", GenerateTimeStamp() },
                { "oauth_version", "1.0" }
            };

            var parameterBuilder = new StringBuilder();
            foreach (var authorizationKey in authorizationParts)
            {
                parameterBuilder.AppendFormat("{0}={1}&", Uri.EscapeDataString(authorizationKey.Key), Uri.EscapeDataString(authorizationKey.Value));
            }
            parameterBuilder.Length--;
            string parameterString = parameterBuilder.ToString();

            var canonicalizedRequestBuilder = new StringBuilder();
            canonicalizedRequestBuilder.Append(HttpMethod.Post.Method);
            canonicalizedRequestBuilder.Append("&");
            canonicalizedRequestBuilder.Append(Uri.EscapeDataString(RequestTokenEndpoint));
            canonicalizedRequestBuilder.Append("&");
            canonicalizedRequestBuilder.Append(Uri.EscapeDataString(parameterString));

            string signature = ComputeSignature(consumerSecret, null, canonicalizedRequestBuilder.ToString());
            authorizationParts.Add("oauth_signature", signature);

            //--
            var authorizationHeaderBuilder = new StringBuilder();
            authorizationHeaderBuilder.Append("OAuth ");
            foreach (var authorizationPart in authorizationParts)
            {
                authorizationHeaderBuilder.AppendFormat(
                    "{0}=\"{1}\", ", authorizationPart.Key, Uri.EscapeDataString(authorizationPart.Value));
            }
            authorizationHeaderBuilder.Length = authorizationHeaderBuilder.Length - 2;

            var request = new HttpRequestMessage(HttpMethod.Post, RequestTokenEndpoint);
            request.Headers.Add("Authorization", authorizationHeaderBuilder.ToString());

            HttpResponseMessage response = await _httpClient.SendAsync(request, Request.CallCancelled);
            response.EnsureSuccessStatusCode();
            string responseText = await response.Content.ReadAsStringAsync();

            IFormCollection responseParameters = WebHelpers.ParseForm(responseText);
            return new RequestToken { Token = Uri.UnescapeDataString(responseParameters["oauth_token"]), TokenSecret = Uri.UnescapeDataString(responseParameters["oauth_token_secret"]), CallbackConfirmed = true, Properties = properties };
        }

        private async Task<AccessToken> ObtainAccessTokenAsync(string consumerKey, string consumerSecret, RequestToken token)
        {
            _logger.WriteVerbose("ObtainAccessToken");

            string nonce = Guid.NewGuid().ToString("N");

            var authorizationParts = new SortedDictionary<string, string>
            {
                { "oauth_consumer_key", consumerKey },
                { "oauth_nonce", nonce },
                { "oauth_signature_method", "HMAC-SHA1" },
                { "oauth_token", token.Token },
                { "oauth_token_secret", token.TokenSecret },
                { "oauth_timestamp", GenerateTimeStamp() },
                { "oauth_version", "1.0" },
            };

            var parameterBuilder = new StringBuilder();
            foreach (var authorizationKey in authorizationParts)
            {
                parameterBuilder.AppendFormat("{0}={1}&", Uri.EscapeDataString(authorizationKey.Key), Uri.EscapeDataString(authorizationKey.Value));
            }
            parameterBuilder.Length--;
            string parameterString = parameterBuilder.ToString();

            var canonicalizedRequestBuilder = new StringBuilder();
            canonicalizedRequestBuilder.Append(HttpMethod.Post.Method);
            canonicalizedRequestBuilder.Append("&");
            canonicalizedRequestBuilder.Append(Uri.EscapeDataString(AccessTokenEndpoint));
            canonicalizedRequestBuilder.Append("&");
            canonicalizedRequestBuilder.Append(Uri.EscapeDataString(parameterString));

            string signature = ComputeSignature(consumerSecret, token.TokenSecret, canonicalizedRequestBuilder.ToString());
            authorizationParts.Add("oauth_signature", signature);

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
            
            HttpResponseMessage response = await _httpClient.SendAsync(request, Request.CallCancelled);

            if (!response.IsSuccessStatusCode)
            {
                _logger.WriteError("AccessToken request failed with a status code of " + response.StatusCode);
                response.EnsureSuccessStatusCode(); // throw
            }

            string responseText = await response.Content.ReadAsStringAsync();

            IFormCollection responseParameters = WebHelpers.ParseForm(responseText);

            return new AccessToken
            {
                Token = Uri.UnescapeDataString(responseParameters["oauth_token"]),
                TokenSecret = Uri.UnescapeDataString(responseParameters["oauth_token_secret"]),
            };
        }

        private async Task<JObject> ObtainUserProfile(string consumerKey, string consumerSecret, AccessToken token)
        {
            _logger.WriteVerbose("ObtainUserProfile");

            string nonce = Guid.NewGuid().ToString("N");
            string requestUrl = "https://api.tripit.com/v1/get/profile";

            var queryParts = new Dictionary<string, string>
            {
                { "format", "json" }
            };
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
            string parameterString = parameterBuilder.ToString();

            var canonicalizedRequestBuilder = new StringBuilder();
            canonicalizedRequestBuilder.Append(HttpMethod.Get.Method);
            canonicalizedRequestBuilder.Append("&");
            canonicalizedRequestBuilder.Append(Uri.EscapeDataString(requestUrl));
            canonicalizedRequestBuilder.Append("&");
            canonicalizedRequestBuilder.Append(Uri.EscapeDataString(parameterString));

            string signature = ComputeSignature(consumerSecret, token.TokenSecret, canonicalizedRequestBuilder.ToString());
            authorizationParts.Add("oauth_signature", signature);

            var authorizationHeaderBuilder = new StringBuilder();
            authorizationHeaderBuilder.Append("OAuth ");
            foreach (var authorizationPart in authorizationParts)
            {
                authorizationHeaderBuilder.AppendFormat(
                    "{0}=\"{1}\", ", authorizationPart.Key, Uri.EscapeDataString(authorizationPart.Value));
            }
            authorizationHeaderBuilder.Length = authorizationHeaderBuilder.Length - 2;

            requestUrl = WebUtilities.AddQueryString(requestUrl, queryParts);
            var request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
            request.Headers.Add("Authorization", authorizationHeaderBuilder.ToString());
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            HttpResponseMessage response = await _httpClient.SendAsync(request, Request.CallCancelled);

            if (!response.IsSuccessStatusCode)
            {
                _logger.WriteError("AccessToken request failed with a status code of " + response.StatusCode);
                response.EnsureSuccessStatusCode(); // throw
            }

            string responseText = await response.Content.ReadAsStringAsync();
            JObject responseObject = JObject.Parse(responseText);

            JObject profileObject = (JObject)responseObject.SelectToken("Profile");
            if (profileObject != null)
                return profileObject;

            return null;
        }

        private static string GenerateTimeStamp()
        {
            TimeSpan secondsSinceUnixEpocStart = DateTime.UtcNow - Epoch;
            return Convert.ToInt64(secondsSinceUnixEpocStart.TotalSeconds).ToString(CultureInfo.InvariantCulture);
        }

        private static string ComputeSignature(string consumerSecret, string tokenSecret, string signatureData)
        {
            using (var algorithm = new HMACSHA1())
            {
                algorithm.Key = Encoding.ASCII.GetBytes(
                    string.Format(CultureInfo.InvariantCulture,
                        "{0}&{1}",
                        Uri.EscapeDataString(consumerSecret),
                        string.IsNullOrEmpty(tokenSecret) ? string.Empty : Uri.EscapeDataString(tokenSecret)));
                byte[] hash = algorithm.ComputeHash(Encoding.ASCII.GetBytes(signatureData));
                return Convert.ToBase64String(hash);
            }
        }
    }
}
