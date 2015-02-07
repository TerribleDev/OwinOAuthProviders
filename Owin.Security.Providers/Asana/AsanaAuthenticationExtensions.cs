using System;

namespace Owin.Security.Providers.Asana
{
    public static class AsanaAuthenticationExtensions
    {
        public static IAppBuilder UseAsanaAuthentication(this IAppBuilder app,
            AsanaAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(AsanaAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseAsanaAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseAsanaAuthentication(new AsanaAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}