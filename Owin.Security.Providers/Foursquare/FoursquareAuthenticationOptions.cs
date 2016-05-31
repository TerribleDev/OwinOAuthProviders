using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin.Security;
using Owin.Security.Providers.Foursquare.Provider;

namespace Owin.Security.Providers.Foursquare
{
    public class FoursquareAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        ///     Initializes a new <see cref="FoursquareAuthenticationOptions" />
        /// </summary>
        public FoursquareAuthenticationOptions()
            : base(Constants.DefaultAuthenticationType)
        {
            this.Caption = Constants.DefaultAuthenticationType;
            this.CallbackPath = "/signin-foursquare";
            this.AuthenticationMode = AuthenticationMode.Passive;
            this.BackchannelTimeout = TimeSpan.FromSeconds(60);
        }

        /// <summary>
        ///     Gets or sets the Foursquare supplied Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the Foursquare supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to Foursquare.
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
        ///     Gets or sets timeout value in milliseconds for back channel communications with Foursquare.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The HttpMessageHandler used to communicate with Foursquare.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-foursquare".
        /// </summary>
        public string CallbackPath { get; set; }

        /// <summary>
        ///     Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user
        ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="IFoursquareAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IFoursquareAuthenticationProvider Provider { get; set; }

        /// <summary>
        ///     Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        ///     Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get { return this.Description.Caption; }
            set { this.Description.Caption = value; }
        }
    }
}