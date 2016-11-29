using Owin.Security.Providers.ConstantContact;
using System;

namespace Owin.Security.Providers.ConstantContact
{
    public static class ConstantContactAuthenticationExtensions
    {
        public static IAppBuilder UseConstantContactAuthentication(this IAppBuilder app,
            ConstantContactAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(ConstantContactAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseConstantContactAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseConstantContactAuthentication(new ConstantContactAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}