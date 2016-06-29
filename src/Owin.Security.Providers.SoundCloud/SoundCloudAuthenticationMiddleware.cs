using System;
using System.Globalization;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.SoundCloud.Provider;

namespace Owin.Security.Providers.SoundCloud
{
    public class SoundCloudAuthenticationMiddleware : AuthenticationMiddleware<SoundCloudAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public SoundCloudAuthenticationMiddleware(
            OwinMiddleware next,
            IAppBuilder app,
            SoundCloudAuthenticationOptions options) : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(Options.ClientId))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "ClientId"));
            if (string.IsNullOrWhiteSpace(Options.ClientSecret))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "ClientSecret"));

            _logger = app.CreateLogger<SoundCloudAuthenticationProvider>();

            if (Options.Provider == null)
                Options.Provider = new SoundCloudAuthenticationProvider();

            if (Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(
                    typeof (SoundCloudAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (string.IsNullOrEmpty(Options.SignInAsAuthenticationType))
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();

            _httpClient = new HttpClient(ResolveHttpMessageHandler(Options))
            {
                Timeout = Options.BackchannelTimeout,
                MaxResponseContentBufferSize = 1024*1024*10
            };
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Microsoft Owin SoundCloud middleware");
            _httpClient.DefaultRequestHeaders.ExpectContinue = false;
        }

        protected override AuthenticationHandler<SoundCloudAuthenticationOptions> CreateHandler()
        {
            return new SoundCloudAuthenticationHandler(_httpClient, _logger);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(SoundCloudAuthenticationOptions options)
        {
            var handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator == null) return handler;
            // Set the cert validate callback
            var webRequestHandler = handler as WebRequestHandler;
            if (webRequestHandler == null)
            {
                throw new InvalidOperationException(Resources.Exception_ValidatorHandlerMismatch);
            }
            webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;

            return handler;
        }
    }
}