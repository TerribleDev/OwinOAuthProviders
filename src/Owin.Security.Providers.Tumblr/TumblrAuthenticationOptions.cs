using System;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.Providers.Tumblr.Messages;
using Owin.Security.Providers.Tumblr.Provider;

namespace Owin.Security.Providers.Tumblr
{
    public class TumblrAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to Tumblr.
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
        ///     The HttpMessageHandler used to communicate with Tumblr.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with Tumblr.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-Tumblr".
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
        ///     Gets or sets the Tumblr supplied App Key
        /// </summary>
        public string AppKey { get; set; }

        /// <summary>
        ///     Gets or sets the Tumblr supplied App Secret
        /// </summary>
        public string AppSecret { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="ITumblrAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public ITumblrAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// A list of permissions to request.
        /// </summary>
        public string Scope { get; set; }

        /// <summary>
        ///     Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user
        ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        ///     Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<RequestToken> StateDataFormat { get; set; }

        /// <summary>
        ///     Initializes a new <see cref="TumblrAuthenticationOptions" />
        /// </summary>
        public TumblrAuthenticationOptions()
            : base("Tumblr")
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-tumblr");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = "basic";
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }
    }
}
