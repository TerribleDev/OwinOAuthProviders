namespace Owin.Security.Providers.Shopify
{
    using Microsoft.Owin;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.DataHandler;
    using Microsoft.Owin.Security.DataProtection;
    using Microsoft.Owin.Security.Infrastructure;
    using System;
    using System.Globalization;
    using System.Net.Http;

    public class ShopifyAuthenticationMiddleware : AuthenticationMiddleware<ShopifyAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public ShopifyAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, ShopifyAuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(Options.ApiKey))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "ApiKey"));
            }

            if (string.IsNullOrWhiteSpace(Options.ApiSecret))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "ApiSecret"));
            }

            _logger = app.CreateLogger<ShopifyAuthenticationMiddleware>();
            if (null == Options.Provider)
            {
                Options.Provider = new ShopifyAuthenticationProvider();
            }

            if (null == Options.StateDataFormat)
            {
                var dataProtector = app.CreateDataProtector(typeof(ShopifyAuthenticationMiddleware).FullName, Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (string.IsNullOrWhiteSpace(Options.SignInAsAuthenticationType))
            {
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            _httpClient = new HttpClient(ResolveHttpMessageHandler(Options))
            {
                Timeout = Options.BackchannelTimeout,
                MaxResponseContentBufferSize = 1024 * 1024 * 10
            };

            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Microsoft Owin Shopify middleware");
            _httpClient.DefaultRequestHeaders.ExpectContinue = false;
        }

        /// <summary>
        /// Provides the <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> object for processing authentication-related requests.
        /// </summary>
        /// <returns>An <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> configured with the <see cref="T:Owin.Security.Providers.Shopify.ShopifyAuthenticationOptions" /> supplied to the constructor.</returns>
        protected override AuthenticationHandler<ShopifyAuthenticationOptions> CreateHandler()
        {
            return new ShopifyAuthenticationHandler(_httpClient, _logger);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(ShopifyAuthenticationOptions options)
        {
            var handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            //// If they provided a validator, apply it or fail.
            if (null == options.BackchannelCertificateValidator)
            {
                return handler;
            }

            //// Set the cert validate callback
            var webRequestHandler = handler as WebRequestHandler;
            if (null == webRequestHandler)
            {
                throw new InvalidOperationException(Resources.Exception_ValidatorHandlerMismatch);
            }

            webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            return handler;
        }
    }
}