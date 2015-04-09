using System;
using System.Globalization;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.OpenID;

namespace Owin.Security.Providers.Wargaming
{
    /// <summary>
    /// OWIN middleware for authenticating users using an OpenID provider
    /// </summary>
    public class WargamingAuthenticationMiddleware : OpenIDAuthenticationMiddlewareBase<WargamingAuthenticationOptions>
    {

        /// <summary>
        /// Initializes a <see cref="WargamingAuthenticationMiddleware"/>
        /// </summary>
        /// <param name="next">The next middleware in the OWIN pipeline to invoke</param>
        /// <param name="app">The OWIN application</param>
        /// <param name="options">Configuration options for the middleware</param>
        public WargamingAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, WargamingAuthenticationOptions options)
            : base(next, app, options)
        { }

        protected override AuthenticationHandler<WargamingAuthenticationOptions> CreateSpecificHandler()
        {
            return new WargamingAuthenticationHandler(_httpClient, _logger);
        }
    }
}
