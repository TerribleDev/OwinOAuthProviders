using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace Owin.Security.Providers.Strava.Provider
{
    public class StravaAuthenticationProvider : IStravaAuthenticationProvider
    {
       
        public Func<StravaAuthenticatedContext, Task> OnAuthenticated { get; set; }
        public Func<StravaReturnEndpointContext, Task> OnReturnEndpoint { get; set; }
        public Action<StravaApplyRedirectContext> OnApplyRedirect { get; set; }

        public StravaAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
            OnApplyRedirect = context =>
                context.Response.Redirect(context.RedirectUri);
        }

        public virtual void ApplyRedirect(StravaApplyRedirectContext context)
        {
            OnApplyRedirect(context);
        }

        public Task Authenticated(StravaAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public Task ReturnEndpoint(StravaReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}