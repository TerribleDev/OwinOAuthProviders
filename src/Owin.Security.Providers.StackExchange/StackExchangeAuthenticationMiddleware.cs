using System;
using System.Globalization;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.Providers.StackExchange
{
    public class StackExchangeAuthenticationMiddleware : AuthenticationMiddleware<StackExchangeAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public StackExchangeAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app,
            StackExchangeAuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(Options.ClientId))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "ClientId"));
            if (string.IsNullOrWhiteSpace(Options.ClientSecret))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "ClientSecret"));
            if (string.IsNullOrWhiteSpace(Options.Key))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "Key"));

            _logger = app.CreateLogger<StackExchangeAuthenticationMiddleware>();

            if (Options.Provider == null)
                Options.Provider = new StackExchangeAuthenticationProvider();

            if (Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(
                    typeof (StackExchangeAuthenticationMiddleware).FullName,
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
        }

        /// <summary>
        ///     Provides the <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> object for processing
        ///     authentication-related requests.
        /// </summary>
        /// <returns>
        ///     An <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> configured with the
        ///     <see cref="T:Owin.Security.Providers.StackExchange.StackExchangeAuthenticationOptions" /> supplied to the constructor.
        /// </returns>
        protected override AuthenticationHandler<StackExchangeAuthenticationOptions> CreateHandler()
        {
            return new StackExchangeAuthenticationHandler(_httpClient, _logger);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(StackExchangeAuthenticationOptions options)
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