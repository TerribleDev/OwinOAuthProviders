namespace Owin.Security.Providers.Imgur.Provider
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    /// <summary></summary>
    public class ImgurReturnEndpointContext : ReturnEndpointContext
    {
        /// <summary></summary>
        /// <param name="context"></param>
        /// <param name="ticket"></param>
        public ImgurReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}
