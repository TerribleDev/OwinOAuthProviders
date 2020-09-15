namespace Owin.Security.Providers.Ping
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Claims;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.Owin;
    using Microsoft.Owin.Infrastructure;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;
    using Owin.Security.Providers.Ping.Helper;
    using Owin.Security.Providers.Ping.Messages;
    using Owin.Security.Providers.Ping.Provider;
    public class PingAuthenticationHandler : AuthenticationHandler<PingAuthenticationOptions>
    {
        #region Constants

        /// <summary>The xml schema string.</summary>
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        /// <summary>The ping error code.</summary>
        private const string PingErrorCode = "error";

        /// <summary>The ping error description code.</summary>
        private const string PingErrorDescriptionCode = "error_description";

        #endregion

        private readonly ILogger Logger;
        private readonly HttpClient HttpClient;

        public PingAuthenticationHandler(HttpClient HttpClient, ILogger Logger)
        {
            this.HttpClient = HttpClient;
            this.Logger = Logger;
        }


        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                //Read Query String Parameter Value
                Microsoft.Owin.IReadableStringCollection query = GetQueryString(ref code, ref state);
                properties = Options.StateDataFormat.Unprotect(state);

                if (properties == null)
                {
                    return null;
                }
                if (code == null)
                {
                    throw new Exception(query["error"] + " - " + query["error_description"]);
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, this.Logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                // Set information for current request in case is missing
                if (string.IsNullOrEmpty(this.Options.Endpoints.TokenEndpoint))
                {
                    await this.DoMetadataDiscoveryAsync();
                }

                //Obtain Token Information
                var tokenResponse = await ObtainAccessTokenAsync(state, code, properties);
                var accessToken = tokenResponse.AccessToken;
                var identityToken = tokenResponse.IdToken;
                var refreshToken = tokenResponse.RefreshToken;

                // Obtain User Profile
                JObject userCard = await ObtainUserProfile(accessToken);

                var context = new PingAuthenticatedContext(Context, userCard, accessToken, identityToken, refreshToken)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType)
                };

                PingAuthenticationHandlerHelper.EnsureAcceptedNetwork(Options.AcceptedNetworks, context.Network);

                //Set Indentity Information
                SetIdentityClaims(accessToken, identityToken, refreshToken, context);

                context.Properties = properties;

                await this.Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                this.Logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        private void SetIdentityClaims(string accessToken, string identityToken, string refreshToken, PingAuthenticatedContext context)
        {
            if (!string.IsNullOrEmpty(context.Id))
            {
                context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, this.Options.AuthenticationType));
            }

            if (!string.IsNullOrEmpty(context.UserName))
            {
                context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.UserName, XmlSchemaString, this.Options.AuthenticationType));
            }

            if (!string.IsNullOrEmpty(context.Email))
            {
                context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, this.Options.AuthenticationType));
            }

            if (!string.IsNullOrEmpty(context.Name))
            {
                context.Identity.AddClaim(new Claim("urn:ping:name", context.Name, XmlSchemaString, this.Options.AuthenticationType));
            }

            if (!string.IsNullOrEmpty(accessToken))
            {
                context.Identity.AddClaim(new Claim(Constants.OAuth2Constants.AccessToken, accessToken, XmlSchemaString, this.Options.AuthenticationType));
            }

            if (!string.IsNullOrEmpty(identityToken))
            {
                context.Identity.AddClaim(new Claim(Constants.OAuth2Constants.IdentityToken, identityToken, XmlSchemaString, this.Options.AuthenticationType));
            }

            if (!string.IsNullOrEmpty(refreshToken))
            {
                context.Identity.AddClaim(new Claim(Constants.OAuth2Constants.RefreshToken, refreshToken, XmlSchemaString, this.Options.AuthenticationType));
            }
        }

        private Microsoft.Owin.IReadableStringCollection GetQueryString(ref string code, ref string state)
        {
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

            return query;
        }

        /// <summary>The apply response challenge async.</summary>
        /// <returns>The <see cref="Task"/>.</returns>
        protected override async Task ApplyResponseChallengeAsync()
        {
            if (this.Response.StatusCode != 401)
            {
                return;
            }

            var challenge = this.Helper.LookupChallenge(
                this.Options.AuthenticationType,
                this.Options.AuthenticationMode);

            if (challenge != null)
            {
                // Call Ping OpenIdConnect Metadata Endpoint to resolve values
                await this.DoMetadataDiscoveryAsync();

                var context = new PingAuthenticatingContext(this.Context, this.Options);
                await this.Options.Provider.Authenticating(context);

                var baseUri = Scheme() + Uri.SchemeDelimiter + this.Request.Host + this.Request.PathBase;
                var currentUri = baseUri + this.Request.Path + this.Request.QueryString;
                var redirectUri = baseUri + this.Options.CallbackPath;

                var properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // Add nonce
                var nonce = Guid.NewGuid().ToString();
                properties.Dictionary.Add("nonce", nonce);

                // OAuth2 10.12 CSRF
                this.GenerateCorrelationId(properties);

                // space separated
                var scope = string.Join(" ", this.Options.Scope);
                var acrValues = string.Join(" ", this.Options.AcrValues);

                var state = this.Options.StateDataFormat.Protect(properties);

                // Get prompt from current request
                var prompt = string.Empty;
                var query = this.Request.Query;
                var values = query.GetValues("prompt");
                if (values != null && values.Count == 1)
                {
                    prompt = values[0];
                }

                var explicitParameters = new Dictionary<string, string>
                                             {
                                                 { Constants.OAuth2Constants.ResponseType, Constants.OAuth2Constants.ResponseTypes.Code },
                                                 { Constants.OAuth2Constants.ClientId, Uri.EscapeDataString(this.Options.ClientId) },
                                                 { Constants.OAuth2Constants.RedirectUri, Uri.EscapeDataString(redirectUri) },
                                                 { Constants.OAuth2Constants.Scope, Uri.EscapeDataString(scope) },
                                                 { Constants.OAuth2Constants.State, Uri.EscapeDataString(state) },
                                                 { Constants.OAuth2Constants.PartnerIdpId, Uri.EscapeDataString(this.Options.PartnerIdpId ?? string.Empty) },
                                                 { Constants.OAuth2Constants.IdpAdapterId, Uri.EscapeDataString(this.Options.IdpAdapterId ?? string.Empty) },
                                                 { Constants.OAuth2Constants.Nonce, Uri.EscapeDataString(nonce) },
                                                 { Constants.OAuth2Constants.Prompt, Uri.EscapeDataString(prompt) },
                                                 { Constants.OAuth2Constants.AcrValues, Uri.EscapeDataString(acrValues) }
                                             };

                var requestParameters = PingAuthenticationHandlerHelper.MergeAdditionalKeyValuePairsIntoExplicitKeyValuePairs(explicitParameters, this.Options.AdditionalParameters);
                var authorizationEndpoint = this.Options.Endpoints.AuthorizationEndpoint + requestParameters.ToQueryString();
                this.Response.Redirect(authorizationEndpoint);
            }
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        /// <summary>The invoke reply path async.</summary>
        /// <returns>The <see cref="Task"/>.</returns>
        private async Task<bool> InvokeReplyPathAsync()
        {
            // This is always invoked on each request. For passive middleware, only do anything if this is
            // for our callback path when the user is redirected back from the authentication provider.
            if (this.Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path && this.Request.User == null)
            {
                // Check for error responses.
                string error;
                string errorDescription;
                var isErrorRequest = PingAuthenticationHandlerHelper.RequestHasErrorMessages(this.Request, out error, out errorDescription);
                if (isErrorRequest)
                {
                    // add a redirect hint that sign-in failed because of ping errors
                    this.LogErrorResult(error, errorDescription);
                    var errorPath = this.ErrorPath();
                    if (!string.IsNullOrEmpty(error))
                        errorPath = WebUtilities.AddQueryString(errorPath, PingErrorCode, error);
                    if (!string.IsNullOrEmpty(errorDescription))
                        errorPath = WebUtilities.AddQueryString(errorPath, PingErrorDescriptionCode, errorDescription);
                    this.Response.Redirect(errorPath);
                    return true;
                }

                // Authenticate
                var ticket = await this.AuthenticateAsync();
                if (ticket == null)
                {
                    this.Logger.WriteWarning("Invalid return state, unable to redirect.");
                    this.Response.StatusCode = 500;

                    // add a redirect hint that sign-in failed in some way
                    var errorPath = this.ErrorPath();
                    errorPath = WebUtilities.AddQueryString(errorPath, PingErrorCode, "invalid return state");

                    this.Response.Redirect(errorPath);
                    return true;
                }

                // Execute provider event
                var context = new PingReturnEndpointContext(this.Context, ticket)
                {
                    SignInAsAuthenticationType = this.Options.SignInAsAuthenticationType,
                    RedirectUri = ticket.Properties.RedirectUri
                };

                await this.Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null && context.Identity != null)
                {
                    // Authentication Succeed
                    var grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }

                    this.Logger.WriteInformation(string.Format("Authentication successful for user: {0}", grantIdentity.Name));
                    this.Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    var redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = this.ErrorPath();
                        redirectUri = WebUtilities.AddQueryString(redirectUri, PingErrorCode, "access_denied");
                    }

                    this.Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }

            return false;
        }

        /// <summary>The do metadata discovery async.</summary>
        /// <returns>The <see cref="Task"/>.</returns>
        /// //TODO: Move this to Helper Method
        private async Task DoMetadataDiscoveryAsync()
        {
            if (this.Options.DiscoverMetadata)
            {
                var response = await this.HttpClient.GetStringAsync(this.Options.PingBaseUrl + this.Options.Endpoints.MetadataEndpoint);
                var endpoints = JsonConvert.DeserializeObject<MetadataEndpoint>(response);
                this.Options.Endpoints.AuthorizationEndpoint = endpoints.AuthorizationEndpoint;
                this.Options.Endpoints.TokenEndpoint = endpoints.TokenEndpoint;
                this.Options.Endpoints.UserInfoEndpoint = endpoints.UserInfoEndpoint;
                this.Options.Endpoints.PingEndSessionEndpoint = endpoints.PingEndSessionEndpoint;
                this.Options.Endpoints.PingRevokedSrisEndpoint = endpoints.PingRevokedSrisEndpoint;
                this.Options.Endpoints.RevocationEndpoint = endpoints.RevocationEndpoint;
            }
        }

        private async Task<AccsessToken> ObtainAccessTokenAsync(string state, string code, AuthenticationProperties properties)
        {
            // Call on token request
            var tokenRequestContext = new PingTokenRequestContext(this.Context, this.Options, state, code, properties);
            await this.Options.Provider.TokenRequest(tokenRequestContext);
            var redirectUri = string.Empty;

            if (string.IsNullOrEmpty(this.Options.RedirectUrl))
            {
                var requestPrefix = Scheme() + Uri.SchemeDelimiter + this.Request.Host + this.Request.PathBase;
                redirectUri = requestPrefix + Options.CallbackPath;
            }

            // Build up the body for the token request
            var body = new List<KeyValuePair<string, string>>
                               {
                                   new KeyValuePair<string, string>(Constants.OAuth2Constants.GrantType, Constants.OAuth2Constants.GrantTypes.AuthorizationCode),
                                   new KeyValuePair<string, string>(Constants.OAuth2Constants.Code, code),
                                   new KeyValuePair<string, string>(Constants.OAuth2Constants.RedirectUri, redirectUri)
                               };

            var isClientSecretEmpty = string.IsNullOrEmpty(this.Options.ClientSecret);
            if (isClientSecretEmpty)
            {
                body.Add(
                    new KeyValuePair<string, string>(Constants.OAuth2Constants.ClientId, this.Options.ClientId));
            }

            // Request the token
            var requestMessage = new HttpRequestMessage(HttpMethod.Post, this.Options.Endpoints.TokenEndpoint);
            if (!isClientSecretEmpty)
            {
                requestMessage.Headers.Authorization = new AuthenticationHeaderValue(
                    "Basic",
                    PingAuthenticationHandlerHelper.EncodeCredential(this.Options.ClientId, this.Options.ClientSecret));
            }

            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Content = new FormUrlEncodedContent(body);

            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
            ServicePointManager.DefaultConnectionLimit = 9999;

            var tokenResponse = await this.HttpClient.SendAsync(requestMessage);
            var text = await tokenResponse.Content.ReadAsStringAsync();

            // Check if there was an error in the response
            if (!tokenResponse.IsSuccessStatusCode)
            {
                var status = tokenResponse.StatusCode;
                if (status == HttpStatusCode.BadRequest)
                {
                    // Deserialize and Log Error
                    var errorResponse = JsonConvert.DeserializeObject<AccsessToken>(text);
                    this.LogErrorResult(errorResponse.Error, errorResponse.ErrorDescription);
                }

                // Throw error
                tokenResponse.EnsureSuccessStatusCode();
            }

            // Deserializes the token response
            var response = JsonConvert.DeserializeObject<AccsessToken>(text);
            return response;
        }

        private async Task<JObject> ObtainUserProfile(string access_token)
        {
            JObject user = null;
            if (this.Options.RequestUserInfo)
            {
                this.Logger.WriteVerbose("ObtainUserProfile");
                var userRequest = new HttpRequestMessage(HttpMethod.Post, this.Options.Endpoints.UserInfoEndpoint);
                userRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", access_token);
                var userResponse = await this.HttpClient.SendAsync(userRequest, this.Request.CallCancelled);
                string text = await userResponse.Content.ReadAsStringAsync();
                user = JObject.Parse(text);
            }
            return user;
        }

        /// <summary>
        /// TOD: Move to the Helper
        /// </summary>
        /// <returns></returns>
        private string Scheme()
        {
            return this.Options.ForceRedirectUriSchemeHttps ? Uri.UriSchemeHttps : this.Request.Scheme;
        }

        /// <summary>The log error result.</summary>
        /// <param name="error">The error.</param>
        /// <param name="errorDescription">The error description.</param>
        private void LogErrorResult(string error, string errorDescription)
        {
            this.Logger.WriteError(string.Format(CultureInfo.InvariantCulture, "Ping Federate error occurred. error: {0} description: {1}", error, errorDescription));
        }

        /// <summary>The error path.</summary>
        /// <returns>The <see cref="string"/>.</returns>
        private string ErrorPath()
        {
            var baseUri = this.Request.Scheme + Uri.SchemeDelimiter + this.Request.Host + this.Request.PathBase;
            var redirectUri = baseUri + "/" + this.Options.ErrorPath;
            return redirectUri;
        }
    }
}
