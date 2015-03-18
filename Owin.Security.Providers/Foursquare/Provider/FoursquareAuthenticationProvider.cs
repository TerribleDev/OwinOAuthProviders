using System;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Foursquare.Provider
{
	public class FoursquareAuthenticationProvider : IFoursquareAuthenticationProvider
	{
		public FoursquareAuthenticationProvider()
		{
			this.OnAuthenticated = context => Task.FromResult<Object>(null);
			this.OnReturnEndpoint = context => Task.FromResult<Object>(null);
		}

		public Func<FoursquareAuthenticatedContext, Task> OnAuthenticated { get; set; }

		public Func<FoursquareReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

		public virtual Task Authenticated(FoursquareAuthenticatedContext context)
		{
			return this.OnAuthenticated(context);
		}

		public virtual Task ReturnEndpoint(FoursquareReturnEndpointContext context)
		{
			return this.OnReturnEndpoint(context);
		}
	}
}