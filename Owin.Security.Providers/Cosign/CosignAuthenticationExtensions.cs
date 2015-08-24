using System;

namespace Owin.Security.Providers.Cosign
{
    public static class CosignAuthenticationExtensions
    {
        public static IAppBuilder UseCosignAuthentication(this IAppBuilder app,
            CosignAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(CosignAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseCosignAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseCosignAuthentication(new CosignAuthenticationOptions
            {
   
            });
        }
    }
}