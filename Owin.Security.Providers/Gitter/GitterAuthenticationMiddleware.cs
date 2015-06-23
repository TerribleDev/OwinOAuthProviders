using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.Providers.Gitter
{
    public class GitterAuthenticationMiddleware : AuthenticationMiddleware<GitterAuthenticationOptions>
    {
        private readonly HttpClient httpClient;
        private readonly ILogger logger;

        public GitterAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app,
            GitterAuthenticationOptions options)
            : base(next, options)
        {
            
        }

        /// <summary>
        ///     Provides the <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> object for processing
        ///     authentication-related requests.
        /// </summary>
        /// <returns>
        ///     An <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> configured with the
        ///     <see cref="T:Owin.Security.Providers.Gitter.GitterAuthenticationOptions" /> supplied to the constructor.
        /// </returns>
        protected override AuthenticationHandler<GitterAuthenticationOptions> CreateHandler()
        {
            return new GitterAuthenticationHandler(httpClient, logger);
        }
    }
}