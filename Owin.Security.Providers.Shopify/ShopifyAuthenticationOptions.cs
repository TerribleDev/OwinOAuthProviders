namespace Owin.Security.Providers.Shopify
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using System;
    using System.Collections.Generic;
    using System.Net.Http;

    public class ShopifyAuthenticationOptions : AuthenticationOptions
    {
        public class ShopifyAuthenticationEndpoints
        {
            /// <summary>
            /// Endpoint which is used to redirect users to request Shopify shop access.
            /// </summary>
            /// <remarks>Defaults to https://{shop}.myshopify.com/admin/oauth/authorize.</remarks>
            public string AuthorizationEndpoint { get; set; }

            /// <summary>
            /// Endpoint which is used to exchange code for access token
            /// </summary>
            /// <remarks>Defaults to https://{shop}.myshopify.com/admin/oauth/access_token.</remarks>
            public string TokenEndpoint { get; set; }

            /// <summary>
            /// Endpoint which is used to obtain shop information after authentication
            /// </summary>
            /// <remarks>Defaults to https://{shop}.myshopify.com/admin/shop.</remarks>
            public string ShopInfoEndpoint { get; set; }
        }

        private const string DefaultAuthorizationEndPoint = "https://{0}.myshopify.com/admin/oauth/authorize";
        private const string DefaultTokenEndpoint = "https://{0}.myshopify.com/admin/oauth/access_token";
        private const string DefaultShopInfoEndpoint = "https://{0}.myshopify.com/admin/shop";

        /// <summary>
        /// Gets or sets the a pinned certificate validator to use to validate the endpoints used in back channel communications belong to Shopify.
        /// </summary>
        /// <value>The pinned certificate validator.</value>
        /// <remarks>If this property is null then the default certificate checks are performed, validating the subject name and if the signing chain is a trusted party.</remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        /// The HttpMessageHandler used to communicate with Shopify. This cannot be set at the same time as BackchannelCertificateValidator unless the value can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        /// Gets or sets timeout value in milliseconds for back channel communications with Shopify.
        /// </summary>
        /// <value>The back channel timeout in milliseconds.</value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        /// The request path within the application's base path where the user-agent will be returned. The middleware will process this request when it arrives. Default value is "/signin-shopify".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        /// Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get
            {
                return Description.Caption;
            }

            set
            {
                Description.Caption = value;
            }
        }

        /// <summary>
        /// Gets or sets the Shopify app API key.
        /// </summary>
        public string ApiKey { get; set; }

        /// <summary>
        /// Gets or sets the Shopify app API secret.
        /// </summary>
        public string ApiSecret { get; set; }

        /// <summary>
        /// Gets the sets of OAuth endpoints used to authenticate against Shopify shop.
        /// </summary>
        public ShopifyAuthenticationEndpoints Endpoints { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="IShopifyAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IShopifyAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// A list of permissions to request.
        /// </summary>
        public IList<string> Scope { get; private set; }

        /// <summary>
        /// Gets or sets the name of another authentication middleware which will be responsible for actually issuing a shop <see cref="System.Security.Claims.ClaimsIdentity" />.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="ShopifyAuthenticationOptions" /> class.
        /// </summary>
        public ShopifyAuthenticationOptions()
            : base("Shopify")
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-shopify");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string> { "read_content" };
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Endpoints = new ShopifyAuthenticationEndpoints
            {
                AuthorizationEndpoint = DefaultAuthorizationEndPoint,
                TokenEndpoint = DefaultTokenEndpoint,
                ShopInfoEndpoint = DefaultShopInfoEndpoint
            };
        }
    }
}