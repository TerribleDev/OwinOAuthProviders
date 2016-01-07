using System;
using System.Net.Http;
using Owin.Security.Providers.DoYouBuzz.Messages;
using Microsoft.Owin.Security;
using Microsoft.Owin;
using Owin.Security.Providers.DoYouBuzz.Provider;

namespace Owin.Security.Providers.DoYouBuzz
{
    /// <summary>
    /// Options for the DoYouBuzz authentication middleware.
    /// </summary>
    public class DoYouBuzzAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DoYouBuzzAuthenticationOptions"/> class.
        /// </summary>
        public DoYouBuzzAuthenticationOptions()
            : base(Constants.DefaultAuthenticationType)
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-doyoubuzz");
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }

        /// <summary>
        /// Gets or sets the consumer key used to communicate with DoYouBuzz.
        /// </summary>
        /// <value>The consumer key used to communicate with DoYouBuzz.</value>
        public string ConsumerKey { get; set; }

        /// <summary>
        /// Gets or sets the consumer secret used to sign requests to DoYouBuzz.
        /// </summary>
        /// <value>The consumer secret used to sign requests to DoYouBuzz.</value>
        public string ConsumerSecret { get; set; }

        /// <summary>
        /// Gets or sets timeout value in milliseconds for back channel communications with DoYouBuzz.
        /// </summary>
        /// <value>
        /// The back channel timeout.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        /// Gets or sets the a pinned certificate validator to use to validate the endpoints used
        /// in back channel communications belong to DoYouBuzz.
        /// </summary>
        /// <value>
        /// The pinned certificate validator.
        /// </value>
        /// <remarks>If this property is null then the default certificate checks are performed,
        /// validating the subject name and if the signing chain is a trusted party.</remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        /// The HttpMessageHandler used to communicate with DoYouBuzz.
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
        /// Default value is "/signin-DoYouBuzz".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        /// Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user <see cref="System.Security.Claims.ClaimsIdentity"/>.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<RequestToken> StateDataFormat { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="IDoYouBuzzAuthenticationProvider"/> used to handle authentication events.
        /// </summary>
        public IDoYouBuzzAuthenticationProvider Provider { get; set; }
    }
}