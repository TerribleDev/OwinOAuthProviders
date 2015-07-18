using System;

namespace Owin.Security.Providers.Strava
{
    public static class StravaAuthenticationExtensions
    {
        public static IAppBuilder 
            UseStravaAuthentication(this IAppBuilder app,
                                    StravaAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof (StravaAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder 
            UseStravaAuthentication(this IAppBuilder app, 
                                    string clientId, 
                                    string clientSecret)
        {
            return app.UseStravaAuthentication(
                new StravaAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}