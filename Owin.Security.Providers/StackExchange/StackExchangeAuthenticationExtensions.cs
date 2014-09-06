using System;

namespace Owin.Security.Providers.StackExchange
{
    public static class StackExchangeAuthenticationExtensions
    {
        public static IAppBuilder UseStackExchangeAuthentication(this IAppBuilder app,
            StackExchangeAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(StackExchangeAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseStackExchangeAuthentication(this IAppBuilder app, string clientId, string clientSecret, string key)
        {
            return app.UseStackExchangeAuthentication(new StackExchangeAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                Key = key
            });
        }
    }
}