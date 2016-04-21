using System;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using System.Collections.Generic;

namespace Owin.Security.Providers.Jawbone
{
    public class JawboneAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to Jawbone
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
        ///     The HttpMessageHandler used to communicate with Jawbone.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with Jawbone.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-jawbone".
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
        ///     Gets or sets the Jawbone supplied Application Key (client_id)
        /// </summary>
        public string AppKey { get; set; }

        /// <summary>
        ///     Gets or sets the Jawbone supplied Application Secret (client_secret)
        /// </summary>
        public string AppSecret { get; set; }

        /// <summary>
        /// Hostname to use for the endpoints. Override this for connecting to the partner stack.
        /// </summary>
        public string Hostname { get; set; }

        /// <summary>
        /// URI for the redirect.
        /// </summary>
        public string RedirectURI { get; set; }

        /// <summary>
        /// A list of permissions to request.
        /// </summary>
        public IList<string> Scope { get; set; }        

        /// <summary>
        ///     Gets or sets the <see cref="JawboneAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IJawboneAuthenticationProvider Provider { get; set; }

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
        ///     Initializes a new <see cref="JawboneAuthenticationOptions" />
        /// </summary>
        public JawboneAuthenticationOptions()
            : base("Jawbone")
        {
            Caption = Constants.DefaultAuthenticationType;
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Scope = new List<string>
            {
                "basic_read", "extended_read", "location_read", "friends_read",
                "mood_read", "mood_write", "move_read", "move_write",
                "sleep_read", "sleep_write","meal_read", "meal_write",
                "weight_read","weight_write", "generic_event_read", "generic_event_write",
                "heartrate_read"
            };
            CallbackPath = new PathString("/signin-jawbone");
            Hostname = "jawbone.com";
        }
    }
}
