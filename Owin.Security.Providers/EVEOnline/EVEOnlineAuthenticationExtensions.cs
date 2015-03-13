using System;

namespace Owin.Security.Providers.EVEOnline
{
    public static class EVEOnlineAuthenticationExtensions
    {
        public static IAppBuilder UseEVEOnlineAuthentication(this IAppBuilder app, EVEOnlineAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentException("app");
            if (options == null)
                throw new ArgumentException("options");

            app.Use(typeof(EVEOnlineAuthenticationMiddleware), app, options);

            return app;
        }
        public static IAppBuilder UseEVEOnlineAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseEVEOnlineAuthentication(new EVEOnlineAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}
