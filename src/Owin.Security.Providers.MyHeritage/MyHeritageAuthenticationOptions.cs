using System;
using System.Collections.Generic;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.Providers.MyHeritage.Provider;

namespace Owin.Security.Providers.MyHeritage
{
    public class MyHeritageAuthenticationOptions : AuthenticationOptions
    {
        public class MyHeritageAuthenticationEndpoints
        {
            /// <summary>
            /// Endpoint which is used to redirect users to request MyHeritage access
            /// </summary>
            /// <remarks>
            /// Defaults to https://accounts.myheritage.com/oauth2/authorize
            /// </remarks>
            public string AuthorizationEndpoint { get; set; }

            /// <summary>
            /// Endpoint which is used to exchange code for access token
            /// </summary>
            /// <remarks>
            /// Defaults to https://accounts.myheritage.com/oauth2/token
            /// </remarks>
            public string TokenEndpoint { get; set; }

            public string UserEndpoint { get; set; }
        }

        private const string AuthorizationEndPoint = "https://accounts.myheritage.com/oauth2/authorize";
        private const string TokenEndpoint = "https://accounts.myheritage.com/oauth2/token";
        private const string UserEndpoint = "https://familygraph.myheritage.com/me";

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with MyHeritage.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-MyHeritage".
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
        ///     Gets or sets the MyHeritage supplied Client Id
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the MyHeritage supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets the sets of OAuth endpoints used to authenticate against MyHeritage.  Overriding these endpoints allows you to use MyHeritage Enterprise for
        /// authentication.
        /// </summary>
        public MyHeritageAuthenticationEndpoints Endpoints { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="IMyHeritageAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IMyHeritageAuthenticationProvider Provider { get; set; }
        
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
        ///     Initializes a new <see cref="MyHeritageAuthenticationOptions" />
        /// </summary>
        public MyHeritageAuthenticationOptions()
            : base("MyHeritage")
        {
			Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-MyHeritage");
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);			
            Endpoints = new MyHeritageAuthenticationEndpoints
            {
                AuthorizationEndpoint = AuthorizationEndPoint,
                TokenEndpoint = TokenEndpoint,
                UserEndpoint = UserEndpoint,
            };
        }
    }
}