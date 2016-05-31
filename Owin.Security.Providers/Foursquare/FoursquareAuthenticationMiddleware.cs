using System;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.Foursquare.Provider;

namespace Owin.Security.Providers.Foursquare
{
    public class FoursquareAuthenticationMiddleware : AuthenticationMiddleware<FoursquareAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public FoursquareAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, FoursquareAuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(this.Options.ClientId) == true)
            {
                throw new ArgumentException("The 'ClientId' must be provided.");
            }

            if (string.IsNullOrWhiteSpace(this.Options.ClientSecret) == true)
            {
                throw new ArgumentException("The 'ClientSecret' option must be provided.");
            }

            this._logger = app.CreateLogger<FoursquareAuthenticationMiddleware>();

            if (this.Options.Provider == null)
            {
                this.Options.Provider = new FoursquareAuthenticationProvider();
            }

            if (this.Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof(FoursquareAuthenticationMiddleware).FullName, this.Options.AuthenticationType, "v1");
                this.Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (string.IsNullOrEmpty(this.Options.SignInAsAuthenticationType) == true)
            {
                this.Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            this._httpClient = new HttpClient(ResolveHttpMessageHandler(this.Options));
            this._httpClient.Timeout = this.Options.BackchannelTimeout;
            this._httpClient.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
        }

        /// <summary>
        ///     Provides the <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> object for processing
        ///     authentication-related requests.
        /// </summary>
        /// <returns>
        ///     An <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> configured with the
        ///     <see cref="T:Owin.Security.Providers.Foursquare.FoursquareAuthenticationOptions" /> supplied to the constructor.
        /// </returns>
        protected override AuthenticationHandler<FoursquareAuthenticationOptions> CreateHandler()
        {
            return new FoursquareAuthenticationHandler(this._httpClient, this._logger);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(FoursquareAuthenticationOptions options)
        {
            var handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;

                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException("Validator Handler Mismatch");
                }

                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return handler;
        }

    }
}