using System;

namespace Owin.Security.Providers.HealthGraph
{
    public static class HealthGraphAuthenticationExtensions
    {
        public static IAppBuilder UseHealthGraphAuthentication(
            this IAppBuilder app,
            HealthGraphAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(HealthGraphAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseHealthGraphAuthentication(
            this IAppBuilder app, 
            string clientId, 
            string clientSecret)
        {
            return app.UseHealthGraphAuthentication(new HealthGraphAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}