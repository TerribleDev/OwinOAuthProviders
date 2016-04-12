using System;
using System.Threading.Tasks;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.DoYouBuzz
{
    /// <summary>
    /// Default <see cref="IDoYouBuzzAuthenticationProvider"/> implementation.
    /// </summary>
    public class DoYouBuzzAuthenticationProvider : IDoYouBuzzAuthenticationProvider
    {
        /// <summary>
        /// Initializes a <see cref="DoYouBuzzAuthenticationProvider"/>
        /// </summary>
        public DoYouBuzzAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
            OnApplyRedirect = context =>
                context.Response.Redirect(context.RedirectUri);
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<DoYouBuzzAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<DoYouBuzzReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the delegate that is invoked when the ApplyRedirect method is invoked.
        /// </summary>
        public Action<DoYouBuzzApplyRedirectContext> OnApplyRedirect { get; set; }

        /// <summary>
        /// Invoked whenever DoYouBuzz successfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task Authenticated(DoYouBuzzAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task ReturnEndpoint(DoYouBuzzReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the DoYouBuzz middleware
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge </param>
        public virtual void ApplyRedirect(DoYouBuzzApplyRedirectContext context)
        {
            OnApplyRedirect(context);
        }
    }
}