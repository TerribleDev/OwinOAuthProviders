using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.Providers.Fitbit.Provider;

namespace Owin.Security.Providers.Fitbit
{
    public class FitbitAuthenticationOptions : AuthenticationOptions
    {
        public class FitbitAuthenticationEndpoints
        {
            /// <summary>
            /// Endpoint which is used to redirect users to request Fitbit access
            /// </summary>
            /// <remarks>
            /// Defaults to https://www.fitbit.com/oauth2/authorize
            /// </remarks>
            public string AuthorizationEndpoint { get; set; }

            /// <summary>
            /// Endpoint which is used to exchange code for access token
            /// </summary>
            /// <remarks>
            /// Defaults to https://api.fitbit.com/oauth2/token
            /// </remarks>
            public string TokenEndpoint { get; set; }

            public string UserEndpoint { get; set; }
        }

        private const string AuthorizationEndPoint = "https://www.fitbit.com/oauth2/authorize";
        private const string TokenEndpoint = "https://api.fitbit.com/oauth2/token";
        private const string UserEndpoint = "https://api.fitbit.com/1/user/-/profile.json";

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with Fitbit.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-Fitbit".
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
        ///     Gets or sets the Fitbit supplied Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the Fitbit supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets the sets of OAuth endpoints used to authenticate against Fitbit.  Overriding these endpoints allows you to use Fitbit Enterprise for
        /// authentication.
        /// </summary>
        public FitbitAuthenticationEndpoints Endpoints { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="IFitbitAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IFitbitAuthenticationProvider Provider { get; set; }
        
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
        /// Gets or sets the mode of the fitbit authentication page.  Can be none, login, or consent.  Defaults to none.
        /// </summary>
        public string Prompt { get; set; }

        /// <summary>
        ///     Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        ///     Initializes a new <see cref="FitbitAuthenticationOptions" />
        /// </summary>
        public FitbitAuthenticationOptions()
            : base("Fitbit")
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-fitbit");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>
            {
                "activity", "nutrition", "profile", "settings", "sleep", "social", "weight"
            };
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Endpoints = new FitbitAuthenticationEndpoints
            {
                AuthorizationEndpoint = AuthorizationEndPoint,
                TokenEndpoint = TokenEndpoint,
                UserEndpoint = UserEndpoint,
            };
            Prompt = "none";
        }
    }
}