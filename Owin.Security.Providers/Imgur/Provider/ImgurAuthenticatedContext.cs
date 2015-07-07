namespace Owin.Security.Providers.Imgur.Provider
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security.Provider;

    public class ImgurAuthenticatedContext : BaseContext<ImgurAuthenticationOptions>
    {
        public ImgurAuthenticatedContext(IOwinContext context, ImgurAuthenticationOptions options) : base(context, options)
        {
        }
    }
}
