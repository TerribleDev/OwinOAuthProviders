using System;

namespace Owin.Security.Providers.ArcGISOnline
{
    public static class ArcGISOnlineAuthenticationExtensions
    {
        public static IAppBuilder UseArcGISOnlineAuthentication(this IAppBuilder app,
            ArcGISOnlineAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(ArcGISOnlineAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseArcGISOnlineAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseArcGISOnlineAuthentication(new ArcGISOnlineAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}