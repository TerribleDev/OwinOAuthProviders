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

    using Owin.Security.Providers.Imgur.Provider;
    using Owin.Security.Providers.Properties;

    public class ImgurAuthenticationMiddleware : AuthenticationMiddleware<ImgurAuthenticationOptions>
    {
        private readonly HttpClient httpClient;
        private readonly ILogger logger;

        private readonly static string TypeFullName = typeof(ImgurAuthenticationMiddleware).FullName;

        public ImgurAuthenticationMiddleware(OwinMiddleware next, IAppBuilder appBuilder, ImgurAuthenticationOptions options)
            : base(next, options)
        {
            if (appBuilder == null)
            {
                throw new ArgumentNullException("appBuilder");
            }

            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            if (string.IsNullOrWhiteSpace(this.Options.ClientId))
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, Resources.Exception_OptionMustBeProvided, "ClientId"), "options");
            }

            if (string.IsNullOrWhiteSpace(this.Options.ClientSecret))
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, Resources.Exception_OptionMustBeProvided, "ClientSecret"), "options");
            }

            if (this.Options.Provider == null)
            {
                this.Options.Provider = new ImgurAuthenticationProvider();
            }

            if (string.IsNullOrWhiteSpace(this.Options.SignInAsAuthenticationType))
            {
                this.Options.SignInAsAuthenticationType = appBuilder.GetDefaultSignInAsAuthenticationType();
            }

            if (this.Options.StateDataFormat == null)
            {
                var dataProtector = appBuilder.CreateDataProtector(TypeFullName, this.Options.AuthenticationType, "v1");

                this.Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            var httpMessageHandler = ResolveHttpMessageHandler(this.Options);

            this.httpClient = new HttpClient(httpMessageHandler);
            this.logger = appBuilder.CreateLogger<ImgurAuthenticationMiddleware>();
        }

        protected override AuthenticationHandler<ImgurAuthenticationOptions> CreateHandler()
        {
            return new ImgurAuthenticationHandler(this.httpClient, this.logger);
        }

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
