using System;

namespace Owin.Security.Providers.Fitbit
{
    public static class FitbitAuthenticationExtensions
    {
        public static IAppBuilder UseFitbitAuthentication(this IAppBuilder app,
            FitbitAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(FitbitAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseFitbitAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseFitbitAuthentication(new FitbitAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}