using System;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Jawbone
{
   /// <summary>
   /// Default <see cref="JawboneAuthenticationProvider"/> implementation.
   /// </summary>
    public class JawboneAuthenticationProvider : IJawboneAuthenticationProvider
    {
        /// <summary>
        /// Initializes a <see cref="JAwboneAuthenticationProvider"/>
        /// </summary>
        public JawboneAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<JawboneAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<JawboneReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        /// Invoked whenever Jawbone successfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task Authenticated(JawboneAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task ReturnEndpoint(JawboneReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}
