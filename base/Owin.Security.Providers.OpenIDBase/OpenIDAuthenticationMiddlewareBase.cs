using System;
using System.Globalization;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.Providers.OpenIDBase
{
    /// <summary>
    /// OWIN middleware for authenticating users using an OpenID provider
    /// </summary>
    public abstract class OpenIDAuthenticationMiddlewareBase<T> : AuthenticationMiddleware<T> where T : OpenIDAuthenticationOptions
    {
        protected readonly ILogger Logger;
        protected readonly HttpClient HTTPClient;

        /// <summary>
        /// Initializes a <see cref="OpenIDAuthenticationMiddlewareBase{T}"/>
        /// </summary>
        /// <param name="next">The next middleware in the OWIN pipeline to invoke</param>
        /// <param name="app">The OWIN application</param>
        /// <param name="options">Configuration options for the middleware</param>
        protected OpenIDAuthenticationMiddlewareBase(OwinMiddleware next, IAppBuilder app, T options)
            : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(Options.ProviderDiscoveryUri) && string.IsNullOrWhiteSpace(Options.ProviderLoginUri) && Options.AuthenticationType != Constants.DefaultAuthenticationType)
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "ProviderDiscoveryUri"));
            }

            Logger = app.CreateLogger<OpenIDAuthenticationMiddlewareBase<T>>();

            if (Options.Provider == null) Options.Provider = new OpenIDAuthenticationProvider();
                

            if (Options.StateDataFormat == null)
            {
                var dataProtecter = app.CreateDataProtector(typeof(OpenIDAuthenticationMiddlewareBase<T>).FullName, Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtecter);
            }

            if (string.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            HTTPClient = new HttpClient(ResolveHttpMessageHandler(Options))
            {
                Timeout = Options.BackchannelTimeout,
                MaxResponseContentBufferSize = 1024*1024*10
            };
            // 10 MB
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