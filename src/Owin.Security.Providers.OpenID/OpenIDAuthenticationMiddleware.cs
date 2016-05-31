using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.OpenIDBase;

namespace Owin.Security.Providers.OpenID
{
    /// <summary>
    /// OWIN middleware for authenticating users using an OpenID provider
    /// </summary>
    public class OpenIDAuthenticationMiddleware : OpenIDAuthenticationMiddlewareBase<OpenIDAuthenticationOptions>
    {
        /// <summary>
        /// Initializes a <see cref="OpenIDAuthenticationMiddleware"/>
        /// </summary>
        /// <param name="next">The next middleware in the OWIN pipeline to invoke</param>
        /// <param name="app">The OWIN application</param>
        /// <param name="options">Configuration options for the middleware</param>
        public OpenIDAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, OpenIDAuthenticationOptions options)
            : base(next, app, options)
        { }

        protected override AuthenticationHandler<OpenIDAuthenticationOptions> CreateSpecificHandler()
        {
            return new OpenIDAuthenticationHandler(HTTPClient, Logger);
        }
    }
}
