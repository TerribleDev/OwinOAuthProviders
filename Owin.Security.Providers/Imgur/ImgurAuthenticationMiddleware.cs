namespace Owin.Security.Providers.Imgur
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security.Infrastructure;

    public class ImgurAuthenticationMiddleware : AuthenticationMiddleware<ImgurAuthenticationOptions>
    {
        public ImgurAuthenticationMiddleware(OwinMiddleware next, IAppBuilder appBuilder, ImgurAuthenticationOptions options) : base(next, options)
        {
        }

        protected override AuthenticationHandler<ImgurAuthenticationOptions> CreateHandler()
        {
            return new ImgurAuthenticationHandler();
        }
    }
}
