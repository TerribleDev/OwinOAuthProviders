using System;
using System.Threading.Tasks;

namespace Owin.Security.Providers.WSO2
{
    public class WSO2AuthenticationProvider : IWSO2AuthenticationProvider
    {
		public WSO2AuthenticationProvider()
		{
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
            OnApplyRedirect = context =>
                context.Response.Redirect(context.RedirectUri);
		}

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<WSO2AuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<WSO2ReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the delegate that is invoked when the ApplyRedirect method is invoked.
        /// </summary>
        public Action<WSO2ApplyRedirectContext> OnApplyRedirect { get; set; }

        /// <summary>
        /// Invoked whenever it successfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task Authenticated(WSO2AuthenticatedContext context) {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task ReturnEndpoint(WSO2ReturnEndpointContext context) {
            return OnReturnEndpoint(context);
        }

        public virtual void ApplyRedirect(WSO2ApplyRedirectContext context)
        {
            OnApplyRedirect(context);
        }

    }
}