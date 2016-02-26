using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.Orcid
{
    public class OrcidAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to Orcid.
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
        ///     The HttpMessageHandler used to communicate with Orcid.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with Orcid.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-Orcid".
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
        ///     Gets or sets the Orcid supplied Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the Orcid supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets the sets of OAuth endpoints used to authenticate against Orcid.  Overriding these endpoints allows you to use Orcid Enterprise for
        /// authentication.
        /// </summary>
        public OrcidAuthenticationEndpoints Endpoints { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="IOrcidAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public IOrcidAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// A list of permissions to request.
        /// </summary>
        public IList<string> Scope { get; private set; }

        /// <summary>
        /// Specifies how the authorization server prompts the user for reauthentication and reapproval. This parameter is optional. 
        /// The only values Orcid supports are:
        /// login—The authorization server must prompt the user for reauthentication, forcing the user to log in again.
        /// consent—The authorization server must prompt the user for reapproval before returning information to the client.
        /// It is valid to pass both values, separated by a space, to require the user to both log in and reauthorize. 
        /// </summary>
        public string Prompt { get; set; }

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
        ///     Initializes a new <see cref="OrcidAuthenticationOptions" />
        /// </summary>
        public OrcidAuthenticationOptions()
            : base("Orcid")
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-orcid");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>();
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Endpoints = new OrcidAuthenticationEndpoints
            {
                AuthorizationEndpoint = OrcidAuthenticationEndpoints.Default.AuthorizationEndPoint,
                TokenEndpoint = OrcidAuthenticationEndpoints.Default.TokenEndpoint,
                ApiEndpoint = OrcidAuthenticationEndpoints.Default.ApiEndpoint
            };
        }
    }
}