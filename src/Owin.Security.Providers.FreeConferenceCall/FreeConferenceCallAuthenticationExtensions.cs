using System;

namespace Owin.Security.Providers.FreeConferenceCall
{
    public static class FreeConferenceCallAuthenticationExtensions
    {
        public static IAppBuilder UseFreeConferenceCallAuthentication(this IAppBuilder app,
            FreeConferenceCallAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(FreeConferenceCallAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseFreeConferenceCallAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseFreeConferenceCallAuthentication(new FreeConferenceCallAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}