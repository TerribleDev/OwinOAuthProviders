using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.EveOnline
{
    public enum Server
    {
        Tranquility,
        Singularity
    }

    public class EveOnlineAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        ///     Initializes a new <see cref="EveOnlineAuthenticationOptions" />.
        ///		By default the scope is empty, you can add ie. publicData when initializing.
        /// </summary>
        public EveOnlineAuthenticationOptions()
            : base("EveOnline")
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-eveonline");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>();
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Server = Server.Tranquility;
        }

        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to EveOnline.
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
        ///     The HttpMessageHandler used to communicate with EveOnline.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with EveOnline.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-eveonline".
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
        ///     Gets or sets EveOnline supplied Client Id
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets EveOnline supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        ///     Gets or sets the EveOnline Server to authenticate against.
        /// </summary>
        public Server Server { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="IEveOnlineAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IEveOnlineAuthenticationProvider Provider { get; set; }

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

    }
}
