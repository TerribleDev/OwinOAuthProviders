using System;
using System.Globalization;
using System.Net;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.Reddit.Provider;

namespace Owin.Security.Providers.Reddit
{
    public class RedditAuthenticationMiddleware : AuthenticationMiddleware<RedditAuthenticationOptions>
    {
        private readonly HttpClient httpClient;
        private readonly ILogger logger;

        public RedditAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app,
            RedditAuthenticationOptions options)
            : base(next, options)
        {
            if (String.IsNullOrWhiteSpace(Options.ClientId))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture,
                    "Option must be provided {0}", "ClientId"));
            if (String.IsNullOrWhiteSpace(Options.ClientSecret))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture,
                    "Option must be provided {0}", "ClientSecret"));

            logger = app.CreateLogger<RedditAuthenticationMiddleware>();

            if (Options.Provider == null)
                Options.Provider = new RedditAuthenticationProvider();

            if (Options.StateDataFormat == null)
            {
                IDataProtector dataProtector = app.CreateDataProtector(
                    typeof (RedditAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();

            httpClient = new HttpClient(ResolveHttpMessageHandler())
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
        ///     <see cref="T:Owin.Security.Providers.Reddit.RedditAuthenticationOptions" /> supplied to the constructor.
        /// </returns>
        protected override AuthenticationHandler<RedditAuthenticationOptions> CreateHandler()
        {
            return new RedditAuthenticationHandler(httpClient, logger);
        }

        private HttpClientHandler ResolveHttpMessageHandler()
        {
            return new HttpClientHandler
            {
                Credentials = new NetworkCredential(Options.ClientId, Options.ClientSecret)
            };
        }
    }
}