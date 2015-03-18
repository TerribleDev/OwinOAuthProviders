using System;

namespace Owin.Security.Providers.Foursquare
{
    public static class FoursquareAuthenticationExtensions
    {
        public static IAppBuilder UseFoursquareAuthentication(this IAppBuilder app, FoursquareAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            return app.Use(typeof(FoursquareAuthenticationMiddleware), app, options);
        }

        public static IAppBuilder UseFoursquareAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseFoursquareAuthentication(new FoursquareAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}