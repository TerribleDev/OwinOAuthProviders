using System;

namespace Owin.Security.Providers.GooglePlus
{
    public static class GooglePlusAuthenticationExtensions
    {
        public static IAppBuilder UseGooglePlusAuthentication(this IAppBuilder app,
            GooglePlusAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(GooglePlusAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseGooglePlusAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseGooglePlusAuthentication(new GooglePlusAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}