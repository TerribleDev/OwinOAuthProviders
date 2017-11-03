using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.Podbean
{
    /// <summary>
    ///     Provides context information to middleware providers.
    /// </summary>
    public class PodbeanReturnEndpointContext : ReturnEndpointContext
    {
        /// <summary>
        /// </summary>
        /// <param name="context">OWIN environment</param>
        /// <param name="ticket">The authentication ticket</param>
        public PodbeanReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}