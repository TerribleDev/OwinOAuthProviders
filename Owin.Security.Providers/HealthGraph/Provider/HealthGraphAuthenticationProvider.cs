using System;
using System.Threading.Tasks;

namespace Owin.Security.Providers.HealthGraph.Provider
{
    public class HealthGraphAuthenticationProvider : IHealthGraphAuthenticationProvider
    {
        public HealthGraphAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndPoint = context => Task.FromResult<object>(null);
        }

        public Func<HealthGraphAuthenticatedContext, Task> OnAuthenticated { get; set; }

        public Func<HealthGraphReturnEndpointContext, Task> OnReturnEndPoint { get; set; }

        public Task Authenticated(HealthGraphAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public Task ReturnEndpoint(HealthGraphReturnEndpointContext context)
        {
            return OnReturnEndPoint(context);
        }
    }
}