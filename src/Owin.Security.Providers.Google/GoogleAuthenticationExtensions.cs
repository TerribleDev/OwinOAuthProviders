using System;

namespace Owin.Security.Providers.Google
{
    public static class GoogleAuthenticationExtensions
    {
        public static IAppBuilder UseGoogleAuthentication(this IAppBuilder app,
            GoogleAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(GoogleAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseGoogleAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseGoogleAuthentication(new GoogleAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}