using System;

namespace Owin.Security.Providers.EDevlet
{
    public static class EDevletAuthenticationExtensions
    {
        public static IAppBuilder UseEDevletAuthentication(this IAppBuilder app,
            EDevletAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(EDevletAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseEDevletAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseEDevletAuthentication(new EDevletAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}