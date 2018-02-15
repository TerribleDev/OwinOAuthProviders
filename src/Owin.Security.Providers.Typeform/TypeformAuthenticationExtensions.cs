using System;

namespace Owin.Security.Providers.Typeform
{
    public static class TypeformAuthenticationExtensions
    {
        public static IAppBuilder UseTypeformAuthentication(this IAppBuilder app,
            TypeformAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(TypeformAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseTypeformAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseTypeformAuthentication(new TypeformAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}