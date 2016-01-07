using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.DoYouBuzz.Messages;
using System;
using System.Globalization;
using System.Net.Http;
using Owin.Security.Providers.DoYouBuzz.Provider;
using Owin.Security.Providers.Properties;

namespace Owin.Security.Providers.DoYouBuzz
{
    /// <summary>
    /// OWIN middleware for authenticating users using DoYouBuzz
    /// </summary>
    public class DoYouBuzzAuthenticationMiddleware : AuthenticationMiddleware<DoYouBuzzAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a <see cref="DoYouBuzzAuthenticationMiddleware"/>
        /// </summary>
        /// <param name="next">The next middleware in the OWIN pipeline to invoke</param>
        /// <param name="app">The OWIN application</param>
        /// <param name="options">Configuration options for the middleware</param>
        public DoYouBuzzAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, DoYouBuzzAuthenticationOptions options)
            : base(next, options)
        {
            _logger = app.CreateLogger<DoYouBuzzAuthenticationMiddleware>();

            if (string.IsNullOrWhiteSpace(Options.ConsumerSecret))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "ConsumerSecret"));
            }

            if (string.IsNullOrWhiteSpace(Options.ConsumerKey))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "ConsumerKey"));
            }

            SetDefaults(app);

            _httpClient = new HttpClient(ResolveHttpMessageHandler(Options))
            {
                Timeout = Options.BackchannelTimeout,
                MaxResponseContentBufferSize = 1024*1024*10
            };
            _httpClient.DefaultRequestHeaders.Accept.ParseAdd("*/*");
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Microsoft Owin DoYouBuzz middleware");
            _httpClient.DefaultRequestHeaders.ExpectContinue = false;
        }

        /// <summary>
        /// Provides the <see cref="AuthenticationHandler"/> object for processing authentication-related requests.
        /// </summary>
        /// <returns>An <see cref="AuthenticationHandler"/> configured with the <see cref="DoYouBuzzAuthenticationOptions"/> supplied to the constructor.</returns>
        protected override AuthenticationHandler<DoYouBuzzAuthenticationOptions> CreateHandler()
        {
            return new DoYouBuzzAuthenticationHandler(_httpClient, _logger);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(DoYouBuzzAuthenticationOptions options)
        {
            var handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // Set the cert validate callback
            var webRequestHandler = handler as WebRequestHandler;
            if (webRequestHandler == null)
            {
                if (options.BackchannelCertificateValidator != null)
                {
                    throw new InvalidOperationException(Resources.Exception_ValidatorHandlerMismatch);
                }
            }
            else if (options.BackchannelCertificateValidator != null)
            {
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return handler;
        }

        private void SetDefaults(IAppBuilder app)
        {
            if (Options.Provider == null)
            {
                Options.Provider = new DoYouBuzzAuthenticationProvider();
            }
            if (Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof(DoYouBuzzAuthenticationMiddleware).FullName, Options.AuthenticationType, "v1");
                Options.StateDataFormat = new SecureDataFormat<RequestToken>(Serializers.RequestToken, dataProtector, TextEncodings.Base64Url);
            }
            if (string.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }
        }
    }
}