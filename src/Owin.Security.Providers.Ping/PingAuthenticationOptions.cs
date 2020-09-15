namespace Owin.Security.Providers.Ping
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Owin.Security.Providers.Ping.Provider;
    using System;
    using System.Collections.Generic;
    using System.Net.Http;
    public class PingAuthenticationOptions : AuthenticationOptions
    {
        #region Constants

        /// <summary>The authorization end point.</summary>
        public const string AuthorizationEndPoint = "/as/authorization.oauth2";

        /// <summary>The open id connect metadata endpoint.</summary>
        public const string OpenIdConnectMetadataEndpoint = "/.well-known/openid-configuration";

        /// <summary>The token endpoint.</summary>
        public const string TokenEndpoint = "/as/token.oauth2";

        /// <summary>The user info endpoint.</summary>
        public const string UserInfoEndpoint = "/idp/userinfo.openid";

        #endregion


        public PingAuthenticationOptions() : base(Constants.DefaultAuthenticationType)
        {
            this.Caption = "Login with Ping";
            this.CallbackPath = new PathString("/externalcallback");
            this.PartnerIdpId = string.Empty;
            this.AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>
            {
                "openid",
                "profile",
                "email"
            };
            this.BackchannelTimeout = TimeSpan.FromSeconds(60);
            this.ErrorPath = "Error/LoginFailure";
            this.Endpoints = new PingAuthenticationEndpoints
            {
                MetadataEndpoint = OpenIdConnectMetadataEndpoint
            };
            this.RequestUserInfo = true;
            this.DiscoverMetadata = true;
            this.RedirectUrl = string.Empty;
        }

        #region Public Properties

        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to Ping.
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
        ///     The HttpMessageHandler used to communicate with Ping.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with Ping.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-Ping".
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
        ///     Gets or sets the Ping supplied Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the Ping supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="IPingAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IPingAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// A list of permissions to request.
        /// </summary>
        public IList<string> Scope { get; set; }

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
        /// Will only allow logins from users belonging to one of these networks. Leave blank to allow all.
        /// </summary>
        public string[] AcceptedNetworks { get; set; }

        public string ErrorPath { get; set; }

        /// <summary>
        ///     Gets or sets the OAuth endpoints used to authenticate against PingFederate.  Overriding these endpoints allows you
        ///     to use PingFederate Enterprise for
        ///     authentication.
        /// </summary>
        public PingAuthenticationEndpoints Endpoints { get; set; }

        public bool DiscoverMetadata { get; set; }

        public string PingBaseUrl { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether to force the use of Uri.UriSchemeHttps for redirect Uri. Default is false
        /// </summary>
        public bool ForceRedirectUriSchemeHttps { get; set; }

        public string RedirectUrl { get; set; }
        public bool RequestUserInfo { get; set; }

        /// <summary>
        ///     Gets or sets the PingFederate OAuth AS parameter indicating the IdP Adapter Instance ID of the adapter to use for user
        ///     authentication.
        /// </summary>
        /// <remarks>
        ///     This parameter may be overridden by policy based on adapter selector configuration. For example, the OAuth Scope
        ///     Selector could enforce the use of a given adapter based on client-requested scopes
        /// </remarks>
        public string IdpAdapterId { get; set; }

        /// <summary>
        ///     Gets or sets the Authentication Context Class Reference (acr) values for the AS to use when processing an
        ///     Authentication Request. Express as a space-separated string, listing the values in order of preference.
        /// </summary>
        public string AcrValues { get; set; }

        /// <summary>
        ///     Gets or sets a PingFederate OAuth AS parameter indicating the Entity ID/Connection ID of the IdP with whom to initiate Browser
        ///     SSO for user authentication.
        /// </summary>
        public string PartnerIdpId { get; set; }

        /// <summary>
        ///     Gets or sets additional values set in this property will be appended to the authorization request.
        /// </summary>
        public Dictionary<string, string> AdditionalParameters { get; set; }

        #endregion
    }
}
