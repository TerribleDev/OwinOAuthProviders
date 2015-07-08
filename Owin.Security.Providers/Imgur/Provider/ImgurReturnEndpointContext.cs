namespace Owin.Security.Providers.Imgur.Provider
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    public class ImgurReturnEndpointContext : ReturnEndpointContext
    {
        public ImgurReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}
