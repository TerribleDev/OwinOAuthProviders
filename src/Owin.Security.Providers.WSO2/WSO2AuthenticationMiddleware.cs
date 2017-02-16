using System;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.WSO2
{
    public class WSO2AuthenticationMiddleware : AuthenticationMiddleware<WSO2AuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public WSO2AuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, WSO2AuthenticationOptions options) : base(next, options)
        {
			if (string.IsNullOrWhiteSpace(Options.BaseUrl))
				throw new ArgumentException("Base url can not be null.");
			if (string.IsNullOrWhiteSpace(Options.ClientId))
                throw new ArgumentException("Client id can not be null.");
            if (string.IsNullOrWhiteSpace(Options.ClientSecret))
                throw new ArgumentException("Client secret can not be null.");

            _logger = app.CreateLogger<WSO2AuthenticationMiddleware>();

            if (Options.Provider == null)
                Options.Provider = new WSO2AuthenticationProvider();

            if (Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(
                    typeof (WSO2AuthenticationMiddleware).FullName,
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

        protected override AuthenticationHandler<WSO2AuthenticationOptions> CreateHandler()
        {
            return new WSO2AuthenticationHandler(_httpClient, _logger);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(WSO2AuthenticationOptions options)
        {
            var handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator == null) return handler;
            // Set the cert validate callback
            var webRequestHandler = handler as WebRequestHandler;
            if (webRequestHandler == null)
            {
                throw new InvalidOperationException("An ICertificateValidator cannot be specified at the same time as an HttpMessageHandler unless it is a WebRequestHandler.");
            }
            webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;

            return handler;        }        
    }
}
