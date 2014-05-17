using System;

namespace Owin.Security.Providers.Instagram
{
    public static class InstagramAuthenticationExtensions
    {
        public static IAppBuilder UseInstagramInAuthentication(this IAppBuilder app,
            InstagramAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(InstagramAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseInstagramInAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseInstagramInAuthentication(new InstagramAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}
