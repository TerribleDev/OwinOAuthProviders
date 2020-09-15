using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Ping.Provider
{
    using System;
    using System.Threading.Tasks;
    public class PingAuthenticationProvider : IPingAuthenticationProvider
    {
        /// <summary>
        /// Initializes a <see cref="PingAuthenticationProvider"/>
        /// </summary>
        public PingAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
            OnTokenRequest = context => Task.FromResult<object>(null);
            OnAuthenticating = context => Task.FromResult<object>(null);
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<PingAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<PingReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>Gets or sets the on token request.</summary>
        public Func<PingTokenRequestContext, Task> OnTokenRequest { get; set; }

        /// <summary>Invoked prior to the being saved in a local cookie and the browser being redirected to the originally requested URL.</summary>
        public Func<PingAuthenticatingContext, Task> OnAuthenticating { get; set; }

        /// <summary>
        /// Invoked whenever PingAuthenticationProvider successfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task Authenticated(PingAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public virtual Task ReturnEndpoint(PingReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }

        public virtual Task TokenRequest(PingTokenRequestContext context)
        {
            return this.OnTokenRequest(context);
        }

        public virtual Task Authenticating(PingAuthenticatingContext context)
        {
            return this.OnAuthenticating(context);
        }
    }
}
