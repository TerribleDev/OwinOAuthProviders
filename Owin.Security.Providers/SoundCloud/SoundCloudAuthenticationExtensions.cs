using System;

namespace Owin.Security.Providers.SoundCloud
{
    public static class SoundCloudAuthenticationExtensions
    {
        public static IAppBuilder UseSoundCloudAuthentication(this IAppBuilder app,
            SoundCloudAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof (SoundCloudAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseSoundCloudAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseSoundCloudAuthentication(new SoundCloudAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}