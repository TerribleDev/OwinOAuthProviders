using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.Strava.Provider
{
    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class StravaReturnEndpointContext : ReturnEndpointContext
    {
        public StravaReturnEndpointContext( IOwinContext context, 
                                            AuthenticationTicket ticket) 
                                        : base(context, ticket)
        {
        }
    }
}