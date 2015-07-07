namespace Owin.Security.Providers.Imgur
{
    using System;
    using System.Threading.Tasks;

    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;

    public class ImgurAuthenticationHandler : AuthenticationHandler<ImgurAuthenticationOptions>
    {
        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            throw new NotImplementedException();
        }
    }
}
