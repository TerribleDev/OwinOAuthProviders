namespace Owin.Security.Providers.Imgur
{
    /// <summary>imgur extensions for the <see cref="IAppBuilder"/>.</summary>
    public static class ImgurAuthenticationExtensions
    {
        /// <summary>Configures the <see cref="IAppBuilder"/> to use <see cref="ImgurAuthenticationMiddleware"/> to authenticate user.</summary>
        /// <param name="appBuilder">The OWIN <see cref="IAppBuilder"/> to be configured.</param>
        /// <param name="options">The <see cref="ImgurAuthenticationOptions"/> with the settings to be used by the <see cref="ImgurAuthenticationMiddleware"/>.</param>
        /// <returns>The configured <see cref="IAppBuilder"/>.</returns>
        public static IAppBuilder UseImgurAuthentication(this IAppBuilder appBuilder, ImgurAuthenticationOptions options)
        {
            return appBuilder.Use<ImgurAuthenticationMiddleware>(appBuilder, options);
        }
    }
}
