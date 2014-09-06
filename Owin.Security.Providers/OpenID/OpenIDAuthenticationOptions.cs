using System.Collections.Generic;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using System;
using System.Net.Http;

namespace Owin.Security.Providers.OpenID
{
    /// <summary>
    /// Configuration options for <see cref="OpenIDAuthenticationMiddleware"/>
    /// </summary>
    public class OpenIDAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        /// Gets or sets the a pinned certificate validator to use to validate the endpoints used
        /// in back channel communications belong to the OpenID provider.
        /// </summary>
        /// <value>
        /// The pinned certificate validator.
        /// </value>
        /// <remarks>If this property is null then the default certificate checks are performed,
        /// validating the subject name and if the signing chain is a trusted party.</remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        /// Gets or sets timeout value in milliseconds for back channel communications with the OpenID provider.
        /// </summary>
        /// <value>
        /// The back channel timeout.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        /// The HttpMessageHandler used to communicate with the OpenID provider.
        /// This cannot be set at the same time as BackchannelCertificateValidator unless the value 
        /// can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        /// Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        /// <summary>
        /// The request path within the application's base path where the user-agent will be returned.
        /// The middleware will process this request when it arrives.
        /// Default value is "/signin-openid".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        /// Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user <see cref="System.Security.Claims.ClaimsIdentity"/>.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="IOpenIDAuthenticationProvider"/> used to handle authentication events.
        /// </summary>
        public IOpenIDAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// The OpenID provider discovery uri
        /// </summary>
        public string ProviderDiscoveryUri { get; set; }

        /// <summary>
        /// The OpenID provider login uri
        /// </summary>
        public string ProviderLoginUri { get; set; }

        /// <summary>
        /// A list of protocol extensions.
        /// </summary>
        public List<IOpenIDProtocolExtension> ProtocolExtensions { get; set; }


        /// <summary>
        /// Initializes a new <see cref="OpenIDAuthenticationOptions"/>
        /// </summary>
        public OpenIDAuthenticationOptions()
            : base(Constants.DefaultAuthenticationType)
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-openid");
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            ProtocolExtensions = new List<IOpenIDProtocolExtension>();
        }
    }
}
