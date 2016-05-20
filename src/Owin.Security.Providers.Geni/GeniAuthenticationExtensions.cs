using System;

namespace Owin.Security.Providers.Geni
{
    public static class GeniAuthenticationExtensions
    {
        public static IAppBuilder UseGeniAuthentication(this IAppBuilder app,
            GeniAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(GeniAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseGeniAuthentication(this IAppBuilder app, string appKey, string appSecret)
        {
            return app.UseGeniAuthentication(new GeniAuthenticationOptions
            {
                AppKey = appKey,
                AppSecret = appSecret
            });
        }
    }
}