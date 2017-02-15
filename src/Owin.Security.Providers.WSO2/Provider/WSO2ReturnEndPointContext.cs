using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.WSO2 
{
    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class WSO2ReturnEndpointContext : ReturnEndpointContext 
	{
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context">Owin environment</param>
        /// <param name="ticket">The authentication ticket</param>
        public WSO2ReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket) {
        }
    }
}