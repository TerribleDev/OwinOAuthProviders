using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.HealthGraph.Provider
{
    public class HealthGraphReturnEndpointContext : ReturnEndpointContext
    {
        public HealthGraphReturnEndpointContext(IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}