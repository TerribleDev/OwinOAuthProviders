using System;

namespace Owin.Security.Providers.Orcid
{
    public static class OrcidAuthenticationExtensions
    {
        public static IAppBuilder UseOrcidAuthentication(this IAppBuilder app,
            OrcidAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(OrcidAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseOrcidAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseOrcidAuthentication(new OrcidAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}