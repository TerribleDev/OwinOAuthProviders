using System;
using System.Threading.Tasks;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.Xing.Provider
{
    /// <summary>
    /// Default <see cref="IXingAuthenticationProvider"/> implementation.
    /// </summary>
    public class XingAuthenticationProvider : IXingAuthenticationProvider
    {
        /// <summary>
        /// Initializes a <see cref="XingAuthenticationProvider"/>
        /// </summary>
        public XingAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
            OnApplyRedirect = context =>
                context.Response.Redirect(context.RedirectUri);
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<XingAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<XingReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the delegate that is invoked when the ApplyRedirect method is invoked.
        /// </summary>
        public Action<XingApplyRedirectContext> OnApplyRedirect { get; set; }

        /// <summary>
        /// Invoked whenever Xing successfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task Authenticated(XingAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task ReturnEndpoint(XingReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the Xing middleware
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge </param>
        public virtual void ApplyRedirect(XingApplyRedirectContext context)
        {
            OnApplyRedirect(context);
        }
    }
}