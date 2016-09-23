﻿using System.Threading.Tasks;

namespace Owin.Security.Providers.VidZapper.Provider
{
    /// <summary>
    /// Specifies callback methods which the <see cref="VidZapperAuthenticationMiddleware"></see> invokes to enable developer control over the authentication process. />
    /// </summary>
    public interface IVidZapperAuthenticationProvider
    {
        /// <summary>
        /// Invoked whenever VidZapper successfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task Authenticated(VidZapperAuthenticatedContext context);

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task ReturnEndpoint(VidZapperReturnEndpointContext context);
    }
}