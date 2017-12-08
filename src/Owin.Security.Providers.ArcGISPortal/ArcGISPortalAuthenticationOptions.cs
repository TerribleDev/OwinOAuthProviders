using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.ArcGISPortal
{
    public class ArcGISPortalAuthenticationOptions : AuthenticationOptions
    {
        public class ArcGISPortalAuthenticationEndpoints
        {
            /// <summary>
            /// Endpoint which is used to redirect users to request ArcGISPortal access
            /// </summary>
            /// <remarks>
            /// Defaults to https://www.arcgis.com/sharing/rest/oauth2/authorize/
            /// </remarks>
            public string AuthorizationEndpoint { get; set; }

            /// <summary>
            /// Endpoint which is used to exchange code for access token
            /// </summary>
            /// <remarks>
            /// Defaults to https://www.arcgis.com/sharing/rest/oauth2/token/
            /// </remarks>
            public string TokenEndpoint { get; set; }

            /// <summary>
            /// Endpoint which is used to obtain user information after authentication
            /// </summary>
            /// <remarks>
            /// Defaults to https://www.arcgis.com/sharing/rest/community/self
            /// </remarks>
            public string UserInfoEndpoint { get; set; }
        }

        private const string AuthenticationTypeNameDefault = "ArcGIS Portal";

        private const string AuthorizationEndPoint = "arcgis/sharing/rest/oauth2/authorize/";
        private const string TokenEndpoint = "arcgis/sharing/rest/oauth2/token/";
        private const string UserInfoEndpoint = "arcgis/sharing/rest/community/self";

        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to ArcGISPortal.
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
        ///     The HttpMessageHandler used to communicate with ArcGISPortal.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with ArcGISPortal.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-ArcGISPortal".
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
        ///     Gets or sets the ArcGIS Portal Authentication Type Name
        ///     Displayed to the user as the login option, and allows multiple ArcGIS Portal OAuth providers to be configured for use in the same application.
        /// </summary>
        public string AuthenticationTypeName { get; set; }

        /// <summary>
        ///     Gets or sets the ArcGIS Portal Host (where the portal is installed e.g. https://arcgisportal.domain.com)
        /// </summary>
        public string Host { get; set; }

        /// <summary>
        ///     Gets or sets the ArcGISPortal supplied Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the ArcGISPortal supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets the sets of OAuth endpoints used to authenticate against ArcGISPortal.  Overriding these endpoints allows you to use ArcGISPortal Enterprise for
        /// authentication.
        /// </summary>
        public ArcGISPortalAuthenticationEndpoints Endpoints { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="IArcGISPortalAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IArcGISPortalAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// A list of permissions to request.
        /// </summary>
        public IList<string> Scope { get; protected set; }

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
        ///     Initializes a new <see cref="ArcGISPortalAuthenticationOptions" />
        /// </summary>
        public ArcGISPortalAuthenticationOptions(string host, string clientId, string clientSecret) : this(AuthenticationTypeNameDefault, host, clientId, clientSecret) {}

        /// <summary>
        ///     Initializes a new <see cref="ArcGISPortalAuthenticationOptions" />
        /// </summary>
        public ArcGISPortalAuthenticationOptions(string authenticationTypeName, string host, string clientId, string clientSecret) : base(authenticationTypeName)
        {
            AuthenticationTypeName = authenticationTypeName;
            Host = host;
            ClientId = clientId;
            ClientSecret = clientSecret;

            AuthenticationType = AuthenticationTypeName;
            Caption = AuthenticationTypeName;

            CallbackPath = new PathString("/signin-arcgis-portal");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>
            {
                "code"
            };
            BackchannelTimeout = TimeSpan.FromSeconds(60);

            Uri hostUri = new Uri(Host);
            Endpoints = new ArcGISPortalAuthenticationEndpoints
            {
                AuthorizationEndpoint = new Uri(hostUri, AuthorizationEndPoint).ToString(),
                TokenEndpoint = new Uri(hostUri, TokenEndpoint).ToString(),
                UserInfoEndpoint = new Uri(hostUri, UserInfoEndpoint).ToString()
            };
        }
    }
}