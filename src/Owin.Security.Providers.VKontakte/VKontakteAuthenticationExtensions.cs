using System;

namespace Owin.Security.Providers.VKontakte
{
    public static class VKontakteAuthenticationExtensions
    {
        public static IAppBuilder UseVKontakteAuthentication(this IAppBuilder app,
            VKontakteAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(VKontakteAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseVKontakteAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseVKontakteAuthentication(new VKontakteAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}