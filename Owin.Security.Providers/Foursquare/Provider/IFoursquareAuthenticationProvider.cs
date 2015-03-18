using System.Threading.Tasks;

namespace Owin.Security.Providers.Foursquare.Provider
{
    public interface IFoursquareAuthenticationProvider
    {
        Task Authenticated(FoursquareAuthenticatedContext context);

        Task ReturnEndpoint(FoursquareReturnEndpointContext context);
    }
}