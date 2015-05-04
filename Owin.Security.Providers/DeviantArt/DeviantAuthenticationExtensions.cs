using System;
using Owin.Security.Providers.DeviantArt;

namespace Owin.Security.Providers.DeviantArt
{
    public static class DeviantArtAuthenticationExtensions
    {
        /// <summary>
        ///  Login with DeviantArt. http://yourUrl/signin-DeviantArt will be used as the redirect URI
        /// </summary>
        /// <param name="app"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        public static IAppBuilder UseDeviantArtAuthentication(this IAppBuilder app,
            DeviantArtAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(DeviantArtAuthenticationMiddleware), app, options);

            return app;
        }
        /// <summary>
        /// Login with DeviantArt. http://yourUrl/signin-DeviantArt will be used as the redirect URI
        /// </summary>
        /// <param name="app"></param>
        /// <param name="clientId"></param>
        /// <param name="clientSecret"></param>
        /// <returns></returns>
        public static IAppBuilder UseDeviantArtAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseDeviantArtAuthentication(new DeviantArtAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}