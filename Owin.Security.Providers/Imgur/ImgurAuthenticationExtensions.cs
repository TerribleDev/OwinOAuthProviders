namespace Owin.Security.Providers.Imgur
{
    public static class ImgurAuthenticationExtensions
    {
        public static IAppBuilder UseImgurAuthentication(this IAppBuilder appBuilder, ImgurAuthenticationOptions options)
        {
            return appBuilder.Use<ImgurAuthenticationMiddleware>(appBuilder, options);
        }
    }
}
