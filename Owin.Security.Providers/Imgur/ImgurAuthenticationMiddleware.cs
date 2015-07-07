namespace Owin.Security.Providers.Imgur
{
    using Microsoft.Owin;
    using Microsoft.Owin.Security.Infrastructure;

    public class ImgurAuthenticationMiddleware : AuthenticationMiddleware<ImgurAuthenticationOptions>
    {
        public ImgurAuthenticationMiddleware(OwinMiddleware next, ImgurAuthenticationOptions options) : base(next, options)
        {
        }

        protected override AuthenticationHandler<ImgurAuthenticationOptions> CreateHandler()
        {
            return new ImgurAuthenticationHandler();
        }
    }
}
