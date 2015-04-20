using System;
using System.Threading.Tasks;
using Owin.Security.Providers.DeviantArt;

namespace Owin.Security.Providers.DeviantArt.Provider
{
    /// <summary>
    /// Default <see cref="IDeviantArtAuthenticationProvider"/> implementation.
    /// </summary>
    public class DeviantArtAuthenticationProvider : IDeviantArtAuthenticationProvider
    {
        /// <summary>
        /// Initializes a <see cref="DeviantArtAuthenticationProvider"/>
        /// </summary>
        public DeviantArtAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<DeviantArtAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<DeviantArtReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        /// Invoked whenever DeviantArt succesfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task Authenticated(DeviantArtAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task ReturnEndpoint(DeviantArtReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}