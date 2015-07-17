namespace Owin.Security.Providers.Imgur.Provider
{
    using System;
    using System.Threading.Tasks;

    /// <summary>Default <see cref="IImgurAuthenticationProvider"/> implementation.</summary>
    public class ImgurAuthenticationProvider : IImgurAuthenticationProvider
    {
        /// <summary>Creates a new <see cref="ImgurAuthenticationProvider"/>.</summary>
        public ImgurAuthenticationProvider()
        {
            this.OnAuthenticated = context => Task.FromResult<object>(null);
            this.OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        /// <summary>Gets or sets the function that is invoked when the Authenticated method is invoked.</summary>
        public Func<ImgurAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.</summary>
        public Func<ImgurReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>Invoked whenever imgur succesfully authenticates a user.</summary>
        /// <param name="context">The <see cref="ImgurAuthenticatedContext"/> that contains information about the login session and the user's <see cref="System.Security.Claims.ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public Task Authenticated(ImgurAuthenticatedContext context)
        {
            return this.OnAuthenticated(context);
        }

        /// <summary>Invoked prior to the <see cref="System.Security.Claims.ClaimsIdentity"/> being saved in a local cookie and the browser being redirected to the originally requested URL.</summary>
        /// <param name="context">The <see cref="ImgurReturnEndpointContext"/> of the authentication request.</param>
        /// <returns>A <see cref="Task"/> representing the completed operation.</returns>
        public Task ReturnEndpoint(ImgurReturnEndpointContext context)
        {
            return this.OnReturnEndpoint(context);
        }
    }
}
