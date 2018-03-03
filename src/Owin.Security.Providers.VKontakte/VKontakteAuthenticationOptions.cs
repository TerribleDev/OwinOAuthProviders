using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.Providers.VKontakte.Provider;

namespace Owin.Security.Providers.VKontakte
{
    public class VKontakteAuthenticationOptions : AuthenticationOptions
    {
        private const string AuthorizationEndPoint = "https://oauth.vk.com/authorize";
        private const string TokenEndpoint = "https://oauth.vk.com/access_token";
        private const string UserInfoEndpoint = "https://api.vk.com/method/users.get";
        private const string DefaultCallbackPath = "/signin-vkontakte";
        private const string DefaultDisplayMode = "page";
	    private const string DefaultApiVersion = "5.73";

        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to VK.
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
        ///     The HttpMessageHandler used to communicate with VK.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with VK.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-vk".
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
        ///     Gets or sets the VK supplied Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the VK supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets the sets of OAuth endpoints used to authenticate against VK.
        /// </summary>
        public VKontakteAuthenticationEndpoints Endpoints { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="IVKontakteAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IVKontakteAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// A list of permissions to request.
        /// </summary>
        public IList<string> Scope { get; set; }

        /// <summary>
        /// Type of displayed page. Possible values: page, popup and mobile. Default: page.
        /// </summary>
        public string Display { get; set; }

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
	    /// Default API version. Required.
	    /// </summary>
	    /// <remarks>
	    /// Defaults to 5.73
	    /// </remarks>
	    public string ApiVersion { get; set; }

		/// <summary>
		///     Initializes a new <see cref="VKontakteAuthenticationOptions" />
		/// </summary>
		public VKontakteAuthenticationOptions()
            : base(Constants.DefaultAuthenticationType)
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString(DefaultCallbackPath);
            AuthenticationMode = AuthenticationMode.Passive;
            Display = DefaultDisplayMode;
            Scope = new List<string>();
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Endpoints = new VKontakteAuthenticationEndpoints
            {
                AuthorizationEndpoint = AuthorizationEndPoint,
                TokenEndpoint = TokenEndpoint,
                UserInfoEndpoint = UserInfoEndpoint
            };
	        ApiVersion = DefaultApiVersion;
        }
    }
}