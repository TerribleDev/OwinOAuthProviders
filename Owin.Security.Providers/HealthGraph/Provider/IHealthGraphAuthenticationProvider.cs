using System.Threading.Tasks;
using Owin.Security.Providers.GitHub;

namespace Owin.Security.Providers.HealthGraph.Provider
{
    public interface IHealthGraphAuthenticationProvider
    {
        Task Authenticated(HealthGraphAuthenticatedContext context);

        Task ReturnEndpoint(HealthGraphReturnEndpointContext context);
    }
}