
using System;
using System.Threading.Tasks;

namespace Owin.Security.Providers.ConstantContact.Provider
{
    /// <summary>
    /// Default <see cref="IConstantContactAuthenticationProvider"/> implementation.
    /// </summary>
    public class ConstantContactAuthenticationProvider : IConstantContactAuthenticationProvider
    {
        /// <summary>
        /// Initializes a <see cref="ConstantContactAuthenticationProvider"/>
        /// </summary>
        public ConstantContactAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<ConstantContactAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<ConstantContactReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        /// Invoked whenever ConstantContact successfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task Authenticated(ConstantContactAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task ReturnEndpoint(ConstantContactReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}