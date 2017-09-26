using System;

namespace Owin.Security.Providers.ArcGISPortal
{
    public static class ArcGISPortalAuthenticationExtensions
    {
        public static IAppBuilder UseArcGISPortalAuthentication(this IAppBuilder app,
            ArcGISPortalAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(ArcGISPortalAuthenticationMiddleware), app, options);

            return app;
        }
    }
}