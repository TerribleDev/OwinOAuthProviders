#region

using System;

#endregion

namespace Owin.Security.Providers.Podbean
{
    public static class PodbeanAuthenticationExtensions
    {
        public static IAppBuilder UsePodbeanAuthentication(this IAppBuilder app,
            PodbeanAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(PodbeanAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UsePodbeanAuthentication(this IAppBuilder app, string appId, string appSecret)
        {
            return app.UsePodbeanAuthentication(new PodbeanAuthenticationOptions
            {
                AppId = appId,
                AppSecret = appSecret
            });
        }
    }
}