using System.Threading.Tasks;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.DoYouBuzz
{
    /// <summary>
    /// Specifies callback methods which the <see cref="DoYouBuzzAuthenticationMiddleware"></see> invokes to enable developer control over the authentication process. />
    /// </summary>
    public interface IDoYouBuzzAuthenticationProvider
    {
        /// <summary>
        /// Invoked whenever DoYouBuzz successfully authenticates a user
        /// </summary>
        /// <param name="context">Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task Authenticated(DoYouBuzzAuthenticatedContext context);

        /// <summary>
        /// Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task ReturnEndpoint(DoYouBuzzReturnEndpointContext context);

        /// <summary>
        /// Called when a Challenge causes a redirect to authorize endpoint in the DoYouBuzz middleware
        /// </summary>
        /// <param name="context">Contains redirect URI and <see cref="AuthenticationProperties"/> of the challenge </param>
        void ApplyRedirect(DoYouBuzzApplyRedirectContext context);
    }
}