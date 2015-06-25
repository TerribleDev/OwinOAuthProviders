using System;

namespace Owin.Security.Providers.Gitter
{
    public static class GitterAuthenticationExtensions
    {
        public static IAppBuilder UseGitterAuthentication(this IAppBuilder app,
            GitterAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(GitterAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseGitterAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseGitterAuthentication(new GitterAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}