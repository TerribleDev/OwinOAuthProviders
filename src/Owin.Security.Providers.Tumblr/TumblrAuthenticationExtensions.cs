using System;

namespace Owin.Security.Providers.Tumblr
{
    public static class TumblrAuthenticationExtensions
    {
        public static IAppBuilder UseTumblrAuthentication(this IAppBuilder app,
            TumblrAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(TumblrAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseTumblrAuthentication(this IAppBuilder app, string appKey, string appSecret)
        {
            return app.UseTumblrAuthentication(new TumblrAuthenticationOptions
            {
                AppKey = appKey,
                AppSecret = appSecret
            });
        }
    }
}