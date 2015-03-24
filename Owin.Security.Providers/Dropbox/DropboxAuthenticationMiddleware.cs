using System;
using System.Globalization;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.Properties;

namespace Owin.Security.Providers.Dropbox
{
    public class DropboxAuthenticationMiddleware : AuthenticationMiddleware<DropboxAuthenticationOptions>
    {
        private readonly HttpClient httpClient;
        private readonly ILogger logger;

        public DropboxAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app,
            DropboxAuthenticationOptions options)
            : base(next, options)
        {
            if (String.IsNullOrWhiteSpace(Options.AppKey))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "AppKey"));
            if (String.IsNullOrWhiteSpace(Options.AppSecret))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "AppSecret"));

            logger = app.CreateLogger<DropboxAuthenticationMiddleware>();

            if (Options.Provider == null)
                Options.Provider = new DropboxAuthenticationProvider();

            if (Options.StateDataFormat == null)
            {
                IDataProtector dataProtector = app.CreateDataProtector(
                    typeof (DropboxAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();

            httpClient = new HttpClient(ResolveHttpMessageHandler(Options))
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
        ///     <see cref="T:Owin.Security.Providers.Dropbox.DropboxAuthenticationOptions" /> supplied to the constructor.
        /// </returns>
        protected override AuthenticationHandler<DropboxAuthenticationOptions> CreateHandler()
        {
            return new DropboxAuthenticationHandler(httpClient, logger);
        }

        private HttpMessageHandler ResolveHttpMessageHandler(DropboxAuthenticationOptions options)
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