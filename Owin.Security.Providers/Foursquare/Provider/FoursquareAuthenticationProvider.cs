using System;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Foursquare.Provider
{
    /// <summary>
    /// Default <see cref="IFoursquareAuthenticationProvider"/> implementation.
    /// </summary>
    public class FoursquareAuthenticationProvider : IFoursquareAuthenticationProvider
    {
        /// <summary>
        /// Initializes a <see cref="FoursquareAuthenticationProvider"/>
        /// </summary>
        public FoursquareAuthenticationProvider()
        {
            this.OnAuthenticated = context => Task.FromResult<object>(null);
            this.OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<FoursquareAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<FoursquareReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        /// Invoked whenever Foursquare succesfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task Authenticated(FoursquareAuthenticatedContext context)
        {
            return this.OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task ReturnEndpoint(FoursquareReturnEndpointContext context)
        {
            return this.OnReturnEndpoint(context);
        }
    }
}