using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.Yammer.Provider;
using System;
using System.Globalization;
using System.Net;
using System.Net.Http;

namespace Owin.Security.Providers.Yammer
{
    public class YammerAuthenticationMiddleware : AuthenticationMiddleware<YammerAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;
        
        public YammerAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, YammerAuthenticationOptions options) : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(Options.ClientId))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "Option must be provided {0}", "ClientId"));
            if (string.IsNullOrWhiteSpace(Options.ClientSecret))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, "Option must be provided {0}", "ClientSecret"));

            _logger = app.CreateLogger<YammerAuthenticationMiddleware>();

            if (Options.Provider == null)
                Options.Provider = new YammerAuthenticationProvider();

            if (Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(
                    typeof(YammerAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (string.IsNullOrEmpty(Options.SignInAsAuthenticationType))
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();

            _httpClient = new HttpClient(ResolveHttpMessageHandler())
            {
                Timeout = Options.BackchannelTimeout,
                MaxResponseContentBufferSize = 1024 * 1024 * 10
            };
        }

        /// <summary>
        ///     Provides the <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> object for processing
        ///     authentication-related requests.
        /// </summary>
        /// <returns>
        ///     An <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> configured with the
        ///     <see cref="T:Owin.Security.Providers.Yammer.YammerAuthenticationOptions" /> supplied to the constructor.
        /// </returns>
        protected override AuthenticationHandler<YammerAuthenticationOptions> CreateHandler()
        {
            return new YammerAuthenticationHandler(_httpClient, _logger);
        }

        private HttpClientHandler ResolveHttpMessageHandler()
        {
            return new HttpClientHandler
            {
                Credentials = new NetworkCredential(Options.ClientId, Options.ClientSecret)
            };
        }
    }
}
