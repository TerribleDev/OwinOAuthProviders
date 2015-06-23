using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.Providers.Gitter
{
    public class GitterAuthenticationHandler : AuthenticationHandler<GitterAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string TokenEndpoint = "https://gitter.im/login/oauth/token";
        private const string UserInfoEndpoint = "https://api.gitter.im/v1/user";
        private const string AuthorizeEndpoint = "https://gitter.im/login/oauth/authorize";

        private readonly ILogger logger;
        private readonly HttpClient httpClient;

        public GitterAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this.httpClient = httpClient;
            this.logger = logger;
        }

        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            throw new NotImplementedException();
        }
    }
}