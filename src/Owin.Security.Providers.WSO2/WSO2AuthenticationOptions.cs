using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.WSO2
{
    public class WSO2AuthenticationOptions : AuthenticationOptions
    {
        public WSO2AuthenticationOptions() : base(Constants.DefaultAuthenticationType)
        {
			Caption = Constants.DefaultAuthenticationType;
			CallbackPath = new PathString("/signin-wso2");
			AuthenticationMode = AuthenticationMode.Passive;
			BackchannelTimeout = TimeSpan.FromSeconds(60);
		}

        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to WSO2
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
        ///     The HttpMessageHandler used to communicate with WSO2.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with WSO2.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

		/// <summary>
		///     Get or sets the text that the user can display on a sign in user interface.
		/// </summary>
		public string Caption
		{
			get { return Description.Caption; }
			set { Description.Caption = value; }
		}

		public string ClientId { get; set; }

		public string ClientSecret { get; set;}

		public string BaseUrl { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-linkedin".
        /// </summary>
        public PathString CallbackPath { get; set; }

        public IWSO2AuthenticationProvider Provider { get; set;}

        /// <summary>
        ///     Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

		/// <summary>
		/// A list of permissions to request.
		/// </summary>
		public IList<string> Scope { get; private set; }

		/// <summary>
		///     Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user
		///     <see cref="System.Security.Claims.ClaimsIdentity" />.
		/// </summary>
		public string SignInAsAuthenticationType { get; set; }
	}
}
