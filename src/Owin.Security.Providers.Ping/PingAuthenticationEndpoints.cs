using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Ping
{
    public class PingAuthenticationEndpoints
    {
        #region Public Properties

        /// <summary>
        ///     Gets or sets Endpoint which is used to redirect users to request PingFederate access
        /// </summary>
        /// <remarks>
        ///     Defaults to /as/authorization.oauth2
        /// </remarks>
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        ///     Gets or sets This public endpoint provides metadata needed for an OAuth client to interface with PingFederate using
        ///     the OpenID
        ///     Connect protocol.
        /// </summary>
        public string MetadataEndpoint { get; set; }

        /// <summary>
        ///     Gets or sets the session end endpoint.
        ///     Asynchronous Front-Channel Logout provides OpenID Connect Clients the capability to initiate single logout requests
        ///     to sign off associated SLO-enabled sessions;
        ///     the logout request endpoint is /idp/startSLO.ping (see IdP Endpoints).
        /// </summary>
        /// <remarks>
        ///     More information: https://documentation.pingidentity.com/display/PF73/Asynchronous+Front-Channel+Logout
        /// </remarks>
        public string PingEndSessionEndpoint { get; set; }

        /// <summary>
        ///     Gets or sets the revoked SRIS endpoint.
        ///     PingFederate includes a REST-based Web Service for Back-Channel Session Revocation.
        ///     This service enables OAuth clients to add sessions to the revocation list or to query their revocation status.
        /// </summary>
        /// <remarks>
        ///     The Grant Access to Session Revocation API option must be selected in its client configuration.
        ///     More information: https://documentation.pingidentity.com/display/PF73/Back-Channel+Session+Revocation
        /// </remarks>
        public string PingRevokedSrisEndpoint { get; set; }

        /// <summary>
        ///     Gets or sets the revocation endpoint.
        ///     The token revocation endpoint is defined in the OAuth 2.0 Token Revocation (RFC 7009) specification.
        ///     It allows clients to notify the authorization server that a previously obtained refresh or access token is no
        ///     longer needed.
        /// </summary>
        /// <remarks>
        ///     The revocation request invalidates the actual token and possibly other tokens based on the same authorization
        ///     grant.
        /// </remarks>
        public string RevocationEndpoint { get; set; }

        /// <summary>
        ///     Gets or sets Endpoint which is used to exchange code for access token
        /// </summary>
        /// <remarks>
        ///     Defaults to /as/token.oauth2
        /// </remarks>
        public string TokenEndpoint { get; set; }

        /// <summary>
        ///     Gets or sets Endpoint which is used to obtain user information after authentication
        /// </summary>
        /// <remarks>
        ///     Defaults to /idp/userinfo.openid
        /// </remarks>
        public string UserInfoEndpoint { get; set; }

        #endregion
    }
}
