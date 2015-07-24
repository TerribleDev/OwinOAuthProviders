using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.Backlog
{
    public class BacklogAuthenticationOptions : AuthenticationOptions
    {
        private const string TempTokenEndpoint = "https://contractname.backlog.jp/api/v2/oauth2/token";
        private const string TempUserInfoEndpoint = "https://contractname.backlog.jp/api/v2/users/myself";
        private const string TempAuthorizationEndpoint = "https://contractname.backlog.jp/OAuth2AccessRequest.action";

        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to Google+.
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
        ///     The HttpMessageHandler used to communicate with Google+.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with Google+.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is empty.
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
        ///     Gets or sets the Google supplied Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the Google supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        ///     Gets or sets the ContractName for Backlog.It's also subdomain at the url of service.ex: https://contractName.backlog.jp/
        /// </summary>
        public string ContractName { get; set; }


        public string TokenEndpoint
        {
            get
            {
                var ub = new UriBuilder(TempTokenEndpoint);
                ub.Host = ub.Host.Replace("contractname", this.ContractName);

                return ub.Uri.ToString();
            }
        }

        public string UserInfoEndpoint
        {
            get
            {
                var ub = new UriBuilder(TempUserInfoEndpoint);
                ub.Host = ub.Host.Replace("contractname", this.ContractName);

                return ub.Uri.ToString();
            }
        }

        public string AuthorizationEndpoint
        {
            get
            {
                var ub = new UriBuilder(TempAuthorizationEndpoint);
                ub.Host = ub.Host.Replace("contractname", this.ContractName);

                return ub.Uri.ToString();
            }
        }

        /// <summary>
        ///     Gets or sets the <see cref="IBacklogAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IBacklogAuthenticationProvider Provider { get; set; }

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
        ///     Initializes a new <see cref="BacklogAuthenticationOptions" />
        /// </summary>
        public BacklogAuthenticationOptions()
            : base("Backlog")
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-backlog");
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }
    }
}