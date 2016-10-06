using System;

namespace Owin.Security.Providers.Box
{
    public static class BoxAuthenticationExtensions
    {
        public static IAppBuilder UseBoxAuthentication(this IAppBuilder app,
            BoxAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(BoxAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseBoxAuthentication(this IAppBuilder app, string appKey, string appSecret)
        {
            return app.UseBoxAuthentication(new BoxAuthenticationOptions
            {
                ClientId = appKey,
                ClientSecret = appSecret
            });
        }
    }
}