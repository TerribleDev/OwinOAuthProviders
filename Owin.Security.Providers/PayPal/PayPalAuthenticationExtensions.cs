using System;

namespace Owin.Security.Providers.PayPal
{
    public static class PayPalAuthenticationExtensions
    {
        public static IAppBuilder UsePayPalAuthentication(this IAppBuilder app,
            PayPalAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(PayPalAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UsePayPalAuthentication(this IAppBuilder app, string clientId, string clientSecret, bool isSandbox=false)
        {
            return app.UsePayPalAuthentication(new PayPalAuthenticationOptions(isSandbox)
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}