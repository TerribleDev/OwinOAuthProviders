namespace Owin.Security.Providers.Imgur.Provider
{
    using System.Threading.Tasks;

    /// <summary>Specifies callback methods which the <see cref="ImgurAuthenticationMiddleware"/> invokes to enable developers control over the authentication process.</summary>
    public interface IImgurAuthenticationProvider
    {
        /// <summary>Invoked whenever imgur succesfully authenticates a user.</summary>
        /// <param name="context">The <see cref="ImgurAuthenticatedContext"/> that contains information about the login session and the user's <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task Authenticated(ImgurAuthenticatedContext context);

        /// <summary>Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.</summary>
        /// <param name="context">The <see cref="ImgurReturnEndpointContext"/> of the authentication request.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        Task ReturnEndpoint(ImgurReturnEndpointContext context);
    }
}
