using System;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.Providers.Onshape
{
    public class OnshapeAuthenticationMiddleware : AuthenticationMiddleware<OnshapeAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public OnshapeAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app,
            OnshapeAuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(Options.AppKey))
                throw new ArgumentException("AppKey must be provided");
            if (string.IsNullOrWhiteSpace(Options.AppSecret))
                throw new ArgumentException("AppSecret must be provided");

            _logger = app.CreateLogger<OnshapeAuthenticationMiddleware>();

            if (Options.Provider == null)
                Options.Provider = new OnshapeAuthenticationProvider();

            if (Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(
                    typeof (OnshapeAuthenticationMiddleware).FullName,
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
        ///     <see cref="T:Owin.Security.Providers.Onshape.OnshapeAuthenticationOptions" /> supplied to the constructor.
        /// </returns>
        protected override AuthenticationHandler<OnshapeAuthenticationOptions> CreateHandler()
        {
            return new OnshapeAuthenticationHandler(_httpClient, _logger);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(OnshapeAuthenticationOptions options)
        {
            var handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator == null) return handler;
            // Set the cert validate callback
            var webRequestHandler = handler as WebRequestHandler;
            if (webRequestHandler == null)
            {
                throw new InvalidOperationException("Validator Handler Mismatch");
            }
            webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;

            return handler;
        }
    }
}