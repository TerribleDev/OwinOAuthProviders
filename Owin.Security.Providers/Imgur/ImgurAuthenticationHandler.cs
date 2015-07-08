namespace Owin.Security.Providers.Imgur
{
    using System;
    using System.Net.Http;
    using System.Threading.Tasks;

    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;

    public class ImgurAuthenticationHandler : AuthenticationHandler<ImgurAuthenticationOptions>
    {
        private readonly HttpClient httpClient;
        private readonly ILogger logger;

        public ImgurAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            if (httpClient == null)
            {
                throw new ArgumentNullException("httpClient");
            }

            if (logger == null)
            {
                throw new ArgumentNullException("logger");
            }

            this.httpClient = httpClient;
            this.logger = logger;
        }

        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            throw new NotImplementedException();
        }
    }
}
