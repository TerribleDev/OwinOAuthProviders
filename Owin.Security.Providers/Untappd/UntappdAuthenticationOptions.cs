using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.Untappd
{
    public class UntappdAuthenticationOptions : AuthenticationOptions
    {
        public class UntappdAuthenticationEndpoints
        {
            /// <summary>
            /// Endpoint which is used to redirect users to request Untappd access
            /// </summary>
            /// <remarks>
            /// Defaults to https://untappd.com/oauth/authenticate/
            /// </remarks>
            public string AuthorizationEndpoint { get; set; }

            /// <summary>
            /// Endpoint which is used to exchange code for access token
            /// </summary>
            /// <remarks>
            /// Defaults to https://untappd.com/oauth/authorize
            /// </remarks>
            public string TokenEndpoint { get; set; }

            /// <summary>
            /// Endpoint which is used to obtain user information after authentication
            /// </summary>
            /// <remarks>
            /// Defaults tohttps://untappd.com/v4/user/info
            /// </remarks>
            public string UserInfoEndpoint { get; set; }
        }

        private const string AuthorizationEndPoint = "https://untappd.com/oauth/authenticate";
        private const string TokenEndpoint = "https://untappd.com/oauth/authorize";
        private const string UserInfoEndpoint = "https://api.untappd.com/v4/user/info";

        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to Untappd.
        /// </summary>
        /// <value>
        ///     The pinned certificate validator.
        /// </value>
        /// <remarks>
        ///     If this property is null then the default certificate checks are performed,
        ///     validating the subject name and if the signing chain is a trusted party.
        /// </remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        ///     The HttpMessageHandler used to communicate with Untappd.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with Untappd.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-Untappd".
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
        ///     Gets or sets the Untappd supplied Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the Untappd supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets the sets of OAuth endpoints used to authenticate against Untappd.  Overriding these endpoints allows you to use Untappd Enterprise for
        /// authentication.
        /// </summary>
        public UntappdAuthenticationEndpoints Endpoints { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="IUntappdAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IUntappdAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// A list of permissions to request.
        /// </summary>
        public IList<string> Scope { get; private set; }

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
        ///     Initializes a new <see cref="UntappdAuthenticationOptions" />
        /// </summary>
        public UntappdAuthenticationOptions()
            : base("Untappd")
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-untappd");
            AuthenticationMode = AuthenticationMode.Passive;
            //untappd has no scopes AFAIK
            Scope = new List<string>{};
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Endpoints = new UntappdAuthenticationEndpoints
            {
                AuthorizationEndpoint = AuthorizationEndPoint,
                TokenEndpoint = TokenEndpoint,
                UserInfoEndpoint = UserInfoEndpoint
            };
        }
    }
}