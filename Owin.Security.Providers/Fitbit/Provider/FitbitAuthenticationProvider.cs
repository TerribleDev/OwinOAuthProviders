using System;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Fitbit.Provider
{
    /// <summary>
    /// Default <see cref="IFitbitAuthenticationProvider"/> implementation.
    /// </summary>
    public class FitbitAuthenticationProvider : IFitbitAuthenticationProvider
    {
        /// <summary>
        /// Initializes a <see cref="FitbitAuthenticationProvider"/>
        /// </summary>
        public FitbitAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<FitbitAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<FitbitReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        /// Invoked whenever Fitbit succesfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task Authenticated(FitbitAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task ReturnEndpoint(FitbitReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}