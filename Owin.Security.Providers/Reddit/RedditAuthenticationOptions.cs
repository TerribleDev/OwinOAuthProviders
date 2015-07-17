using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.Providers.Reddit.Provider;

namespace Owin.Security.Providers.Reddit
{
    public class RedditAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to Reddit.
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
        ///     The HttpMessageHandler used to communicate with Reddit.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with Reddit.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-Reddit".
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
        ///     Gets or sets the Reddit supplied Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the Reddit supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="IRedditAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IRedditAuthenticationProvider Provider { get; set; }

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

        /// <summary>
        ///     Gets or sets the User-Agent string sent with token requests to Reddit.
        ///     Prefered Format is : "&lt;AppName&gt; ( by /u/&lt;username&gt; )"
        /// </summary>
        public string UserAgent { get; set; }

        /// <summary>
        ///     Initializes a new <see cref="RedditAuthenticationOptions" />
        /// </summary>
        public RedditAuthenticationOptions()
            : base("Reddit")
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-reddit");
            AuthenticationMode = AuthenticationMode.Passive;
            UserAgent = "OWIN OAuth Provider";
            Scope = new List<string>
            {
                "identity",
                "mysubreddits",
                "privatemessages"
            };
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }
    }
}