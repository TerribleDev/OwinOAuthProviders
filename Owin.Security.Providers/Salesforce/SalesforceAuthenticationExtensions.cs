using System;

namespace Owin.Security.Providers.Salesforce
{
    public static class SalesforceAuthenticationExtensions
    {
        public static IAppBuilder UseSalesforceAuthentication(this IAppBuilder app,
            SalesforceAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(SalesforceAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseSalesforceAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseSalesforceAuthentication(new SalesforceAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}