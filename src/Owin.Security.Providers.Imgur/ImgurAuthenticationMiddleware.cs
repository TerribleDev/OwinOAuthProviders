namespace Owin.Security.Providers.Imgur
{
    using System;
    using System.Globalization;
    using System.Net.Http;

    using Microsoft.Owin;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.DataHandler;
    using Microsoft.Owin.Security.DataProtection;
    using Microsoft.Owin.Security.Infrastructure;

    using Provider;

    /// <summary>OWIN authentication middleware for imgur.</summary>
    public class ImgurAuthenticationMiddleware : AuthenticationMiddleware<ImgurAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        private static readonly string TypeFullName = typeof(ImgurAuthenticationMiddleware).FullName;

        /// <summary>Creates a new <see cref="ImgurAuthenticationMiddleware"/>.</summary>
        /// <param name="next">The next <see cref="OwinMiddleware"/> in the configuration chain.</param>
        /// <param name="appBuilder">The OWIN <see cref="IAppBuilder"/> being configured.</param>
        /// <param name="options">The <see cref="ImgurAuthenticationOptions"/> to be used to set up the <see cref="ImgurAuthenticationMiddleware"/>.</param>
        public ImgurAuthenticationMiddleware(OwinMiddleware next, IAppBuilder appBuilder, ImgurAuthenticationOptions options)
            : base(next, options)
        {
            if (appBuilder == null)
            {
                throw new ArgumentNullException(nameof(appBuilder));
            }

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            CheckClientId();
            CheckClientSecret();
            SetProvider();
            SetSignInAsAuthenticationType(appBuilder);
            SetStateDataFormat(appBuilder);

            var httpMessageHandler = ResolveHttpMessageHandler(Options);

            _httpClient = new HttpClient(httpMessageHandler);
            _logger = appBuilder.CreateLogger<ImgurAuthenticationMiddleware>();
        }

        /// <summary>Creates the <see cref="AuthenticationHandler{TOptions}"/> to be used by the <see cref="ImgurAuthenticationMiddleware"/>.</summary>
        /// <returns>The <see cref="AuthenticationHandler{TOptions}"/> to be used by the <see cref="ImgurAuthenticationMiddleware"/>.</returns>
        protected override AuthenticationHandler<ImgurAuthenticationOptions> CreateHandler()
        {
            return new ImgurAuthenticationHandler(_httpClient, _logger);
        }

        /// <summary>Checks that the imgur application client id has been set.</summary>
        private void CheckClientId()
        {
            if (!string.IsNullOrWhiteSpace(Options.ClientId))
            {
                return;
            }

            var message = string.Format(CultureInfo.InvariantCulture, Resources.Exception_OptionMustBeProvided, "ClientId");

            throw new ArgumentException(message);
        }

        /// <summary>Checks that the imgur application client secret has been set.</summary>
        private void CheckClientSecret()
        {
            if (!string.IsNullOrWhiteSpace(Options.ClientSecret))
            {
                return;
            }

            var message = string.Format(CultureInfo.InvariantCulture,Resources.Exception_OptionMustBeProvided,"ClientSecret");

            throw new ArgumentException(message);
        }

        /// <summary>Sets the provider to <see cref="ImgurAuthenticationProvider"/> if it hasn't been set.</summary>
        private void SetProvider()
        {
            if (Options.Provider != null)
            {
                return;
            }

            Options.Provider = new ImgurAuthenticationProvider();
        }

        /// <summary>Sets the name authentication middleware responsible for signing in the user if it hasn't been set.</summary>
        /// <param name="appBuilder">The OWIN <see cref="IAppBuilder"/> being configured.</param>
        private void SetSignInAsAuthenticationType(IAppBuilder appBuilder)
        {
            if (!string.IsNullOrWhiteSpace(Options.SignInAsAuthenticationType))
            {
                return;
            }

            Options.SignInAsAuthenticationType = appBuilder.GetDefaultSignInAsAuthenticationType();
        }

        /// <summary>Sets the data protector to <see cref="PropertiesDataFormat"/> if it hasn't been set.</summary>
        /// <param name="appBuilder">The OWIN <see cref="IAppBuilder"/> being configured.</param>
        private void SetStateDataFormat(IAppBuilder appBuilder)
        {
            if (Options.StateDataFormat != null)
            {
                return;
            }

            var dataProtector =
                appBuilder.CreateDataProtector(
                    TypeFullName,
                    Options.AuthenticationType,
                    ImgurAuthenticationDefaults.Version);

            Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
        }

        /// <summary>Gets the <see cref="HttpMessageHandler"/> to be used for the back channel calls.</summary>
        /// <param name="options">The <see cref="ImgurAuthenticationOptions"/> used to configure the <see cref="ImgurAuthenticationMiddleware"/>.</param>
        /// <returns>The <see cref="HttpMessageHandler"/> to be used for the back channel calls.</returns>
        private static HttpMessageHandler ResolveHttpMessageHandler(ImgurAuthenticationOptions options)
        {
            var httpMessageHandler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            if (options.BackchannelCertificateValidator == null)
            {
                return httpMessageHandler;
            }

            var webRequestHandler = httpMessageHandler as WebRequestHandler;

            if (webRequestHandler == null)
            {
                throw new InvalidOperationException(Resources.Exception_ValidatorHandlerMismatch);
            }

            webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;

            return webRequestHandler;
        }
    }
}
