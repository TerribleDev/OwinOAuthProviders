using System;

namespace Owin.Security.Providers.Yammer
{
    public static class YammerAuthenticationExtensions
    {
        public static IAppBuilder UseYammerAuthentication(this IAppBuilder app, YammerAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(YammerAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseYammerAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseYammerAuthentication(new YammerAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}
