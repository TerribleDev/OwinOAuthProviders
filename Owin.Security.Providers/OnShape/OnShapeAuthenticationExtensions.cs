using System;

namespace Owin.Security.Providers.OnShape
{
    public static class OnShapeAuthenticationExtensions
    {
        public static IAppBuilder UseOnShapeAuthentication(this IAppBuilder app,
            OnShapeAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(OnShapeAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseOnShapeAuthentication(this IAppBuilder app, string appKey, string appSecret)
        {
            return app.UseOnShapeAuthentication(new OnShapeAuthenticationOptions
            {
                AppKey = appKey,
                AppSecret = appSecret
            });
        }
    }
}