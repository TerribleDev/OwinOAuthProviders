using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.Providers.Slack.Provider;
using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Owin.Security.Providers.Slack
{
    public class SlackAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to Slack.
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
        ///     The HttpMessageHandler used to communicate with Slack.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with Slack.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-slack".
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
        ///     Gets or sets the Slack supplied Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the Slack supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="ISlackAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public ISlackAuthenticationProvider Provider { get; set; }

        /// <summary>
        ///     Determines the permissions granted from the application to Slack.
        ///     Options include: identify, read, post, client, and/or admin
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
        ///     Gets or sets the Slack team ID to restrict to. Not required by Slack API.
        /// </summary>
        public string TeamId { get; set; }

        /// <summary>
        ///     Initializes a new <see cref="SlackAuthenticationOptions" />
        /// </summary>
        public SlackAuthenticationOptions()
            : base("Slack")
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-slack");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>();
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            TeamId = "";
        }
    }
}
