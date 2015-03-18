using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.Foursquare.Provider
{
	public class FoursquareReturnEndpointContext : ReturnEndpointContext
	{
		/// <summary>
		/// 
		/// </summary>
		/// <param name="context">OWIN environment</param>
		/// <param name="ticket">The authentication ticket</param>
		public FoursquareReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket)
			: base(context, ticket)
		{
		}
	}
}