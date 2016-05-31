using System;
using System.Globalization;
using System.Net;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.Discord.Provider;

namespace Owin.Security.Providers.Discord
{
    public class DiscordAuthenticationMiddleware : AuthenticationMiddleware<DiscordAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public DiscordAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app,
            DiscordAuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(Options.ClientId))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture,
                    "Option must be provided {0}", "ClientId"));
            if (string.IsNullOrWhiteSpace(Options.ClientSecret))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture,
                    "Option must be provided {0}", "ClientSecret"));

            _logger = app.CreateLogger<DiscordAuthenticationMiddleware>();

            if (Options.Provider == null)
                Options.Provider = new DiscordAuthenticationProvider();

            if (Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(
                    typeof(DiscordAuthenticationMiddleware).FullName,
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
        ///     <see cref="T:Owin.Security.Providers.Discord.DiscordAuthenticationOptions" /> supplied to the constructor.
        /// </returns>
        protected override AuthenticationHandler<DiscordAuthenticationOptions> CreateHandler()
        {
            return new DiscordAuthenticationHandler(_httpClient, _logger);
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