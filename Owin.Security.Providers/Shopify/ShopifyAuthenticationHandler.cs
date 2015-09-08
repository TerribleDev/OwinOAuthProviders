namespace Owin.Security.Providers.Shopify
{
    using Microsoft.Owin.Infrastructure;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Claims;
    using System.Threading.Tasks;

    public class ShopifyAuthenticationHandler : AuthenticationHandler<ShopifyAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private readonly ILogger logger;
        private readonly HttpClient httpClient;

        public ShopifyAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this.httpClient = httpClient;
            this.logger = logger;
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
                if (null != values && 1 == values.Count)
                {
                    code = values[0];
                }

                values = query.GetValues("state");
                if (null != values && 1 == values.Count)
                {
                    state = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(state);
                if (null == properties)
                {
                    return null;
                }

                //// OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                var currentShopifyShopName = properties.Dictionary["ShopName"];
                if (string.IsNullOrWhiteSpace(currentShopifyShopName))
                {
                    return null;
                }

                var requestPrefix = Request.Scheme + "://" + Request.Host;
                var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                //// Build up the body for the token request
                var body = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("redirect_uri", redirectUri),
                    new KeyValuePair<string, string>("client_id", Options.ApiKey),
                    new KeyValuePair<string, string>("client_secret", Options.ApiSecret)
                };

                //// Request the token
                var requestMessage = new HttpRequestMessage(HttpMethod.Post, string.Format(CultureInfo.CurrentCulture, Options.Endpoints.TokenEndpoint, currentShopifyShopName));
                requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                requestMessage.Content = new FormUrlEncodedContent(body);
                var tokenResponse = await httpClient.SendAsync(requestMessage);
                tokenResponse.EnsureSuccessStatusCode();
                var text = await tokenResponse.Content.ReadAsStringAsync();

                //// Deserializes the token response
                dynamic response = JsonConvert.DeserializeObject<dynamic>(text);
                var accessToken = (string)response.access_token;

                //// Get the Shopify shop information
                var shopRequest = new HttpRequestMessage(HttpMethod.Get, string.Format(CultureInfo.CurrentCulture, Options.Endpoints.ShopInfoEndpoint, currentShopifyShopName) + "?access_token=" + Uri.EscapeDataString(accessToken));
                shopRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                var shopResponse = await httpClient.SendAsync(shopRequest, Request.CallCancelled);
                shopResponse.EnsureSuccessStatusCode();
                text = await shopResponse.Content.ReadAsStringAsync();
                var shopifyShop = JObject.Parse(text);
                var context = new ShopifyAuthenticatedContext(Context, shopifyShop, accessToken)
                {
                    Identity = new ClaimsIdentity(Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType)
                };

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

                if (!string.IsNullOrEmpty(context.ShopName))
                {
                    context.Identity.AddClaim(new Claim("urn:shopify:shopdomain", context.ShopifyDomain, XmlSchemaString, Options.AuthenticationType));
                }

                context.Properties = properties;
                await Options.Provider.Authenticated(context);
                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception exception)
            {
                logger.WriteError(exception.Message);
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
            if (challenge == null)
            {
                return Task.FromResult<object>(null);
            }

            var baseUri = Request.Scheme + Uri.SchemeDelimiter + Request.Host + Request.PathBase;
            var currentUri = baseUri + Request.Path + Request.QueryString;
            var redirectUri = baseUri + Options.CallbackPath;

            var properties = challenge.Properties;
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = currentUri;
            }

            //// OAuth2 10.12 CSRF
            GenerateCorrelationId(properties);
            var scope = string.Join(",", Options.Scope);
            var state = Options.StateDataFormat.Protect(properties);
            var authorizationEndpoint = 
                string.Format(CultureInfo.CurrentCulture, Options.Endpoints.AuthorizationEndpoint, challenge.Properties.Dictionary["ShopName"]) +
                "?client_id=" + Uri.EscapeDataString(Options.ApiKey) +
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
            {
                return false;
            }

            //// TODO: error responses (I have no idea what this error responses TODO means :o)
            var ticket = await AuthenticateAsync();
            if (null == ticket)
            {
                logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new ShopifyReturnEndpointContext(Context, ticket)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = ticket.Properties.RedirectUri
            };

            await Options.Provider.ReturnEndpoint(context);
            if (null != context.SignInAsAuthenticationType && null != context.Identity)
            {
                var grantIdentity = context.Identity;
                if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                }

                Context.Authentication.SignIn(context.Properties, grantIdentity);
            }

            if (context.IsRequestCompleted || null == context.RedirectUri)
            {
                return context.IsRequestCompleted;
            }

            var redirectUri = context.RedirectUri;
            if (null == context.Identity)
            {
                //// Add a redirect hint that sign-in failed in some way
                redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
            }

            Response.Redirect(redirectUri);
            context.RequestCompleted();
            return context.IsRequestCompleted;
        }
    }
}