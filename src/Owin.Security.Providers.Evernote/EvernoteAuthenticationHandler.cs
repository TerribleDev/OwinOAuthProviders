using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.Evernote.Messages;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Owin.Helpers;

namespace Owin.Security.Providers.Evernote
{
    public class EvernoteAuthenticationHandler : AuthenticationHandler<EvernoteAuthenticationOptions>
    {
        private const string StateCookie = "_EvernoteState";
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private const string RequestTokenEndpoint = "/oauth";
        private const string AuthenticationEndpoint = "/OAuth.action?oauth_token=";
        private const string AccessTokenEndpoint = "/oauth";

        private const string ProductionBase = "https://www.evernote.com";
        private const string SandBoxBase = "https://sandbox.evernote.com";

        public string BaseUri => Options.IsSandBox ? SandBoxBase : ProductionBase;

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public EvernoteAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;

            _logger.WriteInformation("Authentication Handler initialized");
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

                //var sandboxLnb = bool.Parse(query.Get("sandbox_lnb"));

                var accessToken = await ObtainAccessTokenAsync(Options.AppKey, Options.AppSecret, requestToken, oauthVerifier);

                var context = new EvernoteAuthenticatedContext(Context, accessToken)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType)
                };

                if (!string.IsNullOrEmpty(context.UserId))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.UserId,
                        XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.UserName))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName,
                        XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.FullName))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.FullName,
                        XmlSchemaString, Options.AuthenticationType));
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

        protected override async Task ApplyResponseChallengeAsync()
        {
            _logger.WriteInformation("Applying response challenge");

            if (Response.StatusCode != 401)
            {
                return;
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge == null) return;

            var baseUri =
                Request.Scheme +
                Uri.SchemeDelimiter +
                Request.Host +
                Request.PathBase;

            var callBackUri = baseUri + Options.CallbackPath;

            var properties = challenge.Properties;
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = baseUri + Request.Path + Request.QueryString;
            }

            _logger.WriteInformation("Requesting Token...");

            var requestToken = await ObtainRequestTokenAsync(Options.AppKey, Options.AppSecret, callBackUri, properties);

            _logger.WriteInformation("Token request successfull. Token: " + requestToken.Token);

            var authorizationEndpoint = BaseUri + AuthenticationEndpoint + requestToken.Token;

            if (requestToken.CallbackConfirmed)
            {
                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true,
                    Secure = Request.IsSecure
                };

                Response.StatusCode = 302;
                Response.Cookies.Append(StateCookie, Options.StateDataFormat.Protect(requestToken), cookieOptions);
                Response.Headers.Set("Location", authorizationEndpoint);
            }
            else
            {
                _logger.WriteError("requestToken CallbackConfirmed!=true");
            }
        }

        private async Task<RequestToken> ObtainRequestTokenAsync(string appKey, string appSecret, string callBackUri, AuthenticationProperties properties)
        {
            string normalizedUrl;
            string normalizedRequestParameters;

            var oauthBase = new OAuthBase();
            var url = new Uri(BaseUri + RequestTokenEndpoint);
            var signature = oauthBase.GenerateSignature(
                url,
                appKey,
                appSecret,
                null,
                null,
                "GET",
                oauthBase.GenerateTimeStamp(),
                oauthBase.GenerateNonce(),
                callBackUri, out normalizedUrl, out normalizedRequestParameters);

            normalizedRequestParameters = normalizedRequestParameters + "&oauth_signature=" + HttpUtility.UrlEncode(signature);

            if (normalizedRequestParameters.Length > 0)
                normalizedUrl += "?";

            var authorizationEndpoint = normalizedUrl + normalizedRequestParameters;

            _logger.WriteInformation("Url =" + authorizationEndpoint);

            string query = await WebRequestAsync(HttpMethod.Get, authorizationEndpoint, null);

            if (query?.Length > 0)
            {
                NameValueCollection queryString = HttpUtility.ParseQueryString(query);
                if (queryString["oauth_token"] != null)
                {
                    _logger.WriteInformation("Retrieving data...");

                    return new RequestToken
                    {
                        Token = Uri.UnescapeDataString(queryString["oauth_token"]),
                        CallbackConfirmed = true,
                        Properties = properties
                    };
                }
            }

            return new RequestToken();
        }

        private async Task<bool> InvokeReturnPathAsync()
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

            var context = new EvernoteReturnEndpointContext(Context, ticket)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = ticket.Properties.RedirectUri
            };

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null && context.Identity != null)
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

        private async Task<AccessToken> ObtainAccessTokenAsync(string appKey, string appSecret, RequestToken token, string verifier)
        {
            string normalizedUrl;
            string normalizedRequestParameters;

            var oauthBase = new OAuthBase();
            var url = new Uri(BaseUri + AccessTokenEndpoint);
            var signature = oauthBase.GenerateSignature(
                url,
                appKey,
                appSecret,
                token.Token,
                verifier,
                "POST",
                oauthBase.GenerateTimeStamp(),
                oauthBase.GenerateNonce(),
                "",
                out normalizedUrl, out normalizedRequestParameters);

            var postData = normalizedRequestParameters + "&oauth_signature=" + HttpUtility.UrlEncode(signature);
            var authorizationParts = new SortedDictionary<string, string>();

            foreach (var key in postData.Split('&'))
            {
                authorizationParts.Add(key.Split('=')[0], key.Split('=')[1]);
            }

            var authorizationHeaderBuilder = new StringBuilder();
            authorizationHeaderBuilder.Append("OAuth ");
            foreach (var authorizationPart in authorizationParts)
            {
                authorizationHeaderBuilder.AppendFormat(
                    "{0}=\"{1}\", ", authorizationPart.Key, Uri.EscapeDataString(authorizationPart.Value));
            }
            authorizationHeaderBuilder.Length = authorizationHeaderBuilder.Length - 2;

            string query = await WebRequestAsync(HttpMethod.Post, normalizedUrl, authorizationHeaderBuilder.ToString());

            if (query.Length > 0)
            {
                var responseParameters = HttpUtility.ParseQueryString(query);
                if (responseParameters["oauth_token"] != null)
                {
                    return new AccessToken
                    {
                        Token = Uri.UnescapeDataString(responseParameters["oauth_token"]),
                        Shard = Uri.UnescapeDataString(responseParameters["edam_shard"]),
                        UserId = Uri.UnescapeDataString(responseParameters["edam_userId"]),
                        NoteStoreUrl = Uri.UnescapeDataString(responseParameters["edam_noteStoreUrl"]),
                        WebApiUrlPrefix = Uri.UnescapeDataString(responseParameters["edam_webApiUrlPrefix"]),
                    };
                }
            }

            return new AccessToken();
        }

        private async Task<string> WebRequestAsync(HttpMethod method, string url, string postData)
        {
            try
            {
                var request = new HttpRequestMessage(method, url);

                if (method == HttpMethod.Post)
                    request.Headers.Add("Authorization", postData);

                _logger.WriteInformation("Send request...");

                var response = _httpClient.SendAsync(request, Request.CallCancelled).Result;

                _logger.WriteInformation("Request ended");

                response.EnsureSuccessStatusCode();
                return response.Content.ReadAsStringAsync().Result;
            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message, ex);
            }

            return null;
            //HttpWebRequest webRequest = WebRequest.Create(url) as HttpWebRequest;
            //webRequest.Method = method;
            //webRequest.ServicePoint.Expect100Continue = false;
            //webRequest.UserAgent = "MoreProductiveNow";
            //webRequest.Timeout = 20000;
            //webRequest.Proxy = WebRequest.DefaultWebProxy;
            //webRequest.UseDefaultCredentials = true;
            //if (method == "POST")
            //{
            //    webRequest.ContentType = "application/x-www-form-urlencoded";
            //    StreamWriter streamWriter = new StreamWriter(webRequest.GetRequestStream());
            //    try
            //    {
            //        streamWriter.Write(postData);
            //    }
            //    catch (Exception ex)
            //    {
            //        _logger.WriteError(ex.Message, ex);
            //        throw;
            //    }
            //    finally
            //    {
            //        streamWriter.Close();
            //    }
            //}

            //return await WebResponseGetAsync(webRequest);
        }

        private async Task<string> WebResponseGetAsync(HttpWebRequest webRequest)
        {
            StreamReader streamReader = null;
            try
            {
                var response = await webRequest.GetResponseAsync();
                if (response == null) throw new Exception("Bad request");

                using (var stream = response.GetResponseStream())
                {
                    streamReader = new StreamReader(stream);
                    return streamReader.ReadToEnd();
                }
            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
            }
            finally
            {
                var responseStream = webRequest.GetResponse().GetResponseStream();
                responseStream?.Close();
                streamReader?.Close();
                _logger.WriteInformation("Request closed");
            }

            return null;
        }
    }
}