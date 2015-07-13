namespace Owin.Security.Providers.Imgur.Provider
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    /// <summary>Provide context information to the middleware provider.</summary>
    public class ImgurReturnEndpointContext : ReturnEndpointContext
    {
        /// <summary>Creates a new <see cref="ImgurReturnEndpointContext"/>.</summary>
        /// <param name="context">The OWIN context of the authentication request.</param>
        /// <param name="ticket">The <see cref="AuthenticationTicket" /> of the authentication request.</param>
        public ImgurReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}
