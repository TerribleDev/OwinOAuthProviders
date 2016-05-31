using System;

namespace Owin.Security.Providers.EveOnline
{
    public static class EveOnlineAuthenticationExtensions
    {
        public static IAppBuilder UseEveOnlineAuthentication(this IAppBuilder app, EveOnlineAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentException("app");
            if (options == null)
                throw new ArgumentException("options");

            app.Use(typeof(EveOnlineAuthenticationMiddleware), app, options);

            return app;
        }
        public static IAppBuilder UseEveOnlineAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseEveOnlineAuthentication(new EveOnlineAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}
