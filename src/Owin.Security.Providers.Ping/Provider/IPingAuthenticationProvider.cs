using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Ping.Provider
{
    public interface IPingAuthenticationProvider
    {

        /// <summary>
        /// Invoked whenever Ping successfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task Authenticated(PingAuthenticatedContext context);

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task ReturnEndpoint(PingReturnEndpointContext context);

        /// <summary>Invoked prior to calling the token request endpoint on PingFederate</summary>
        /// <param name="context">The context</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task TokenRequest(PingTokenRequestContext context);

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context">The context</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task Authenticating(PingAuthenticatingContext context);
    }
}
