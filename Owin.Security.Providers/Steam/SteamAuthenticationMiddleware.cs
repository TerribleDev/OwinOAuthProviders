using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.OpenID;

namespace Owin.Security.Providers.Steam
{
    /// <summary>
    /// OWIN middleware for authenticating users using an OpenID provider
    /// </summary>
    public sealed class SteamAuthenticationMiddleware : OpenIDAuthenticationMiddlewareBase<SteamAuthenticationOptions>
    {
        /// <summary>
        /// Initializes a <see cref="SteamAuthenticationMiddleware"/>
        /// </summary>
        /// <param name="next">The next middleware in the OWIN pipeline to invoke</param>
        /// <param name="app">The OWIN application</param>
        /// <param name="options">Configuration options for the middleware</param>
        public SteamAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, SteamAuthenticationOptions options)
            : base(next, app, options)
        { }

        protected override AuthenticationHandler<SteamAuthenticationOptions> CreateSpecificHandler()
        {
            return new SteamAuthenticationHandler(_httpClient, _logger);
        }
    }
}
