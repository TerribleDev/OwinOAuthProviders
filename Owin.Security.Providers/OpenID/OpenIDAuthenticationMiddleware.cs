using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.Properties;
using System;
using System.Globalization;
using System.Net.Http;

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
            return new OpenIDAuthenticationHandler(_httpClient, _logger);
        }
    }

    /// <summary>
    /// OWIN middleware for authenticating users using an OpenID provider
    /// </summary>
    public abstract class OpenIDAuthenticationMiddlewareBase<T> : AuthenticationMiddleware<T> where T : OpenIDAuthenticationOptions
    {
        protected readonly ILogger _logger;
        protected readonly HttpClient _httpClient;

        /// <summary>
        /// Initializes a <see cref="OpenIDAuthenticationMiddlewareBase"/>
        /// </summary>
        /// <param name="next">The next middleware in the OWIN pipeline to invoke</param>
        /// <param name="app">The OWIN application</param>
        /// <param name="options">Configuration options for the middleware</param>
        public OpenIDAuthenticationMiddlewareBase(OwinMiddleware next, IAppBuilder app, T options)
            : base(next, options)
        {
            if (String.IsNullOrWhiteSpace(Options.ProviderDiscoveryUri) && String.IsNullOrWhiteSpace(Options.ProviderLoginUri) && Options.AuthenticationType != Constants.DefaultAuthenticationType)
            {
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "ProviderDiscoveryUri"));
            }

            _logger = app.CreateLogger<OpenIDAuthenticationMiddleware>();

            if (Options.Provider == null)
            {
                Options.Provider = new OpenIDAuthenticationProvider();
            }

            if (Options.StateDataFormat == null)
            {
                IDataProtector dataProtecter = app.CreateDataProtector(
                    typeof(OpenIDAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtecter);
            }

            if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            _httpClient = new HttpClient(ResolveHttpMessageHandler(Options));
            _httpClient.Timeout = Options.BackchannelTimeout;
            _httpClient.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
        }

        /// <summary>
        /// Provides the <see cref="AuthenticationHandler"/> object for processing authentication-related requests.
        /// </summary>
        /// <returns>An <see cref="AuthenticationHandler"/> configured with the <see cref="OpenIDAuthenticationOptions"/> supplied to the constructor.</returns>
        protected override AuthenticationHandler<T> CreateHandler()
        {
            return CreateSpecificHandler();
        }

        /// <summary>
        /// Provides the <see cref="AuthenticationHandler"/> object for processing authentication-related requests.
        /// </summary>
        /// <returns>An <see cref="AuthenticationHandler"/> configured with the <see cref="OpenIDAuthenticationOptions"/> supplied to the constructor.</returns>
        protected abstract AuthenticationHandler<T> CreateSpecificHandler();

        private static HttpMessageHandler ResolveHttpMessageHandler(OpenIDAuthenticationOptions options)
        {
            HttpMessageHandler handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException(Resources.Exception_ValidatorHandlerMismatch);
                }
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return handler;
        }
    }
}
