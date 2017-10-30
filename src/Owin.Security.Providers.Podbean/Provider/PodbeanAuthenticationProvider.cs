#region

using System;
using System.Threading.Tasks;

#endregion

namespace Owin.Security.Providers.Podbean
{
    /// <summary>
    ///     Default <see cref="IPodbeanAuthenticationProvider" /> implementation.
    /// </summary>
    public class PodbeanAuthenticationProvider : IPodbeanAuthenticationProvider
    {
        /// <summary>
        ///     Initializes a <see cref="PodbeanAuthenticationProvider" />
        /// </summary>
        public PodbeanAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        /// <summary>
        ///     Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<PodbeanAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        ///     Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<PodbeanReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        ///     Invoked whenever Podbean successfully authenticates a user
        /// </summary>
        /// <param name="context">
        ///     Contains information about the login session as well as the user
        ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
        /// </param>
        /// <returns>A <see cref="Task" /> representing the completed operation.</returns>
        public virtual Task Authenticated(PodbeanAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        ///     Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity" /> being saved in a local cookie and the
        ///     browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task" /> representing the completed operation.</returns>
        public virtual Task ReturnEndpoint(PodbeanReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}