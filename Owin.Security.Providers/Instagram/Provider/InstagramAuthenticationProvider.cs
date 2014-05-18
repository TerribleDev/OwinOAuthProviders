using System;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Instagram.Provider
{
    /// <summary>
    /// Default <see cref="IInstagramAuthenticationProvider"/> implementation.
    /// </summary>
    public class InstagramAuthenticationProvider : IInstagramAuthenticationProvider
    {
        /// <summary>
        /// Initializes a <see cref="InstagramAuthenticationProvider"/>
        /// </summary>
        public InstagramAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<InstagramAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<InstagramReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        /// Invoked whenever Instagram succesfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task Authenticated(InstagramAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task ReturnEndpoint(InstagramReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}