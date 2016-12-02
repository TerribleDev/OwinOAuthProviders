using System.Threading.Tasks;

namespace Owin.Security.Providers.WSO2
{
	public interface IWSO2AuthenticationProvider 
	{
		Task Authenticated(WSO2AuthenticatedContext context);

		Task ReturnEndpoint(WSO2ReturnEndpointContext context);

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the wso2 middleware
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge </param>
        void ApplyRedirect(WSO2ApplyRedirectContext context);
	}
}