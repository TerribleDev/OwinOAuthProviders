using Microsoft.Owin.Logging;
using System.Net.Http;
using Owin.Security.Providers.OpenIDBase;

namespace Owin.Security.Providers.OpenID
{
    internal class OpenIDAuthenticationHandler : OpenIDAuthenticationHandlerBase<OpenIDAuthenticationOptions>
    {
        public OpenIDAuthenticationHandler(HttpClient httpClient, ILogger logger)
            : base(httpClient, logger)
        { }
    }
}
