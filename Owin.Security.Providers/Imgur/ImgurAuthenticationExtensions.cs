namespace Owin.Security.Providers.Imgur
{
    /// <summary></summary>
    public static class ImgurAuthenticationExtensions
    {
        /// <summary></summary>
        /// <param name="appBuilder"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        public static IAppBuilder UseImgurAuthentication(this IAppBuilder appBuilder, ImgurAuthenticationOptions options)
        {
            return appBuilder.Use<ImgurAuthenticationMiddleware>(appBuilder, options);
        }
    }
}
