using System;
using System.Collections.Generic;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.Providers.Geni.Provider;

namespace Owin.Security.Providers.Geni
{
    public class GeniAuthenticationOptions : AuthenticationOptions
    {
        public class GeniAuthenticationEndpoints
        {
            /// <summary>
            /// Endpoint which is used to redirect users to request Geni access
            /// </summary>
            /// <remarks>
            /// Defaults to https://www.geni.com/oauth2/authorize
            /// </remarks>
            public string AuthorizationEndpoint { get; set; }

            /// <summary>
            /// Endpoint which is used to exchange code for access token
            /// </summary>
            /// <remarks>
            /// Defaults to https://api.geni.com/oauth2/token
            /// </remarks>
            public string TokenEndpoint { get; set; }

            public string UserEndpoint { get; set; }
        }

        private const string AuthorizationEndPoint = "https://www.geni.com/platform/oauth/authorize";
        private const string TokenEndpoint = "https://www.geni.com/platform/oauth/request_token";
        private const string UserEndpoint = "https://geni.com/api/user";

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with Geni.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-Geni".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        ///     Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        /// <summary>
        ///     Gets or sets the Geni supplied App Key
        /// </summary>
        public string AppKey { get; set; }

        /// <summary>
        ///     Gets or sets the Geni supplied App Secret
        /// </summary>
        public string AppSecret { get; set; }

        /// <summary>
        /// Gets the sets of OAuth endpoints used to authenticate against Geni.  Overriding these endpoints allows you to use Geni Enterprise for
        /// authentication.
        /// </summary>
        public GeniAuthenticationEndpoints Endpoints { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="IGeniAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IGeniAuthenticationProvider Provider { get; set; }
        
        /// <summary>
        ///     Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user
        ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        ///     Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        ///     Initializes a new <see cref="GeniAuthenticationOptions" />
        /// </summary>
        public GeniAuthenticationOptions()
            : base("Geni")
        {
			Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-Geni");
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);			
            Endpoints = new GeniAuthenticationEndpoints
            {
                AuthorizationEndpoint = AuthorizationEndPoint,
                TokenEndpoint = TokenEndpoint,
                UserEndpoint = UserEndpoint,
            };
        }
    }
}