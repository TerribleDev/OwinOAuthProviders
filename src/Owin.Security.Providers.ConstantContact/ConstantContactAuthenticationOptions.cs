using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.Providers.ConstantContact.Provider;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.ConstantContact
{
    public class ConstantContactAuthenticationOptions : AuthenticationOptions
    {
        public class ConstantContactAuthenticationEndpoints
        {
            /// <summary>
            /// Endpoint which is used to redirect users to request ConstantContact access
            /// </summary>
            /// <remarks>
            /// Defaults to https://www.ConstantContact.com/oauth2/authorize
            /// </remarks>
            public string AuthorizationEndpoint { get; set; }

            /// <summary>
            /// Endpoint which is used to exchange code for access token
            /// </summary>
            /// <remarks>
            /// Defaults to https://api.ConstantContact.com/oauth2/token
            /// </remarks>
            public string TokenEndpoint { get; set; }

        }

        private const string AuthorizationEndPoint = "https://oauth2.constantcontact.com/oauth2/oauth/siteowner/authorize";
        private const string TokenEndpoint = "https://oauth2.constantcontact.com/oauth2/oauth/token";

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with ConstantContact.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-ConstantContact".
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
        ///     Gets or sets the ConstantContact supplied Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the ConstantContact supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets the sets of OAuth endpoints used to authenticate against ConstantContact.  Overriding these endpoints allows you to use ConstantContact Enterprise for
        /// authentication.
        /// </summary>
        public ConstantContactAuthenticationEndpoints Endpoints { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="IConstantContactAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IConstantContactAuthenticationProvider Provider { get; set; }

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
        ///     Initializes a new <see cref="ConstantContactAuthenticationOptions" />
        /// </summary>
        public ConstantContactAuthenticationOptions()
            : base("ConstantContact")
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-ConstantContact");
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Endpoints = new ConstantContactAuthenticationEndpoints
            {
                AuthorizationEndpoint = AuthorizationEndPoint,
                TokenEndpoint = TokenEndpoint
            };
        }
    }
}
