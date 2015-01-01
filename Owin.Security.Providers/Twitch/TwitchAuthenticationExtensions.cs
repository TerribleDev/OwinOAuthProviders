using System;

namespace Owin.Security.Providers.Twitch
{
    public static class TwitchAuthenticationExtensions
    {
        public static IAppBuilder UseTwitchAuthentication(this IAppBuilder app,
            TwitchAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(TwitchAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseTwitchAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseTwitchAuthentication(new TwitchAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}