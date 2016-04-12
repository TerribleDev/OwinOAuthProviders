using System.Threading.Tasks;

namespace Owin.Security.Providers.HealthGraph.Provider
{
    public interface IHealthGraphAuthenticationProvider
    {
        Task Authenticated(HealthGraphAuthenticatedContext context);

        Task ReturnEndpoint(HealthGraphReturnEndpointContext context);
    }
}