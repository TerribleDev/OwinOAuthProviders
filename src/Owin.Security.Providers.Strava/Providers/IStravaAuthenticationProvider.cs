using System.Threading.Tasks;

namespace Owin.Security.Providers.Strava.Provider
{
    public interface IStravaAuthenticationProvider 
    {
        Task Authenticated(StravaAuthenticatedContext context);
        Task ReturnEndpoint(StravaReturnEndpointContext context);
        void ApplyRedirect(StravaApplyRedirectContext context);
    }
}