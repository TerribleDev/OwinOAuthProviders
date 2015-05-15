using System;

namespace Owin.Security.Providers.Spotify
{
    public static class SpotifyAuthenticationExtensions
    {
        public static IAppBuilder UseSpotifyAuthentication(this IAppBuilder app,
            SpotifyAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(SpotifyAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseSpotifyAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseSpotifyAuthentication(new SpotifyAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}