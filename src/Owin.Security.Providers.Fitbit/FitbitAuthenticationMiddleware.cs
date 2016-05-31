using System;
using System.Globalization;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.Fitbit.Provider;

namespace Owin.Security.Providers.Fitbit
{
    public class FitbitAuthenticationMiddleware : AuthenticationMiddleware<FitbitAuthenticationOptions>
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public FitbitAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app,
            FitbitAuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(Options.ClientId))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "ClientId"));
            if (string.IsNullOrWhiteSpace(Options.ClientSecret))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "ClientSecret"));

            _logger = app.CreateLogger<FitbitAuthenticationMiddleware>();

            if (Options.Provider == null)
                Options.Provider = new FitbitAuthenticationProvider();

            if (Options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(
                    typeof (FitbitAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (string.IsNullOrEmpty(Options.SignInAsAuthenticationType))
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();

            _httpClient = new HttpClient(new WebRequestHandler())
            {
                Timeout = Options.BackchannelTimeout,
                MaxResponseContentBufferSize = 1024*1024*10,
            };
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("Microsoft Owin Fitbit middleware");
            _httpClient.DefaultRequestHeaders.ExpectContinue = false;
        }

        /// <summary>
        ///     Provides the <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> object for processing
        ///     authentication-related requests.
        /// </summary>
        /// <returns>
        ///     An <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> configured with the
        ///     <see cref="T:Owin.Security.Providers.Fitbit.FitbitAuthenticationOptions" /> supplied to the constructor.
        /// </returns>
        protected override AuthenticationHandler<FitbitAuthenticationOptions> CreateHandler()
        {
            return new FitbitAuthenticationHandler(_httpClient, _logger);
        }
    }
}