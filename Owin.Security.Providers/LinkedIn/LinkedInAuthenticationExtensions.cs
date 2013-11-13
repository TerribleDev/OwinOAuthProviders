using System;

namespace Owin.Security.Providers.LinkedIn
{
    public static class LinkedInAuthenticationExtensions
    {
        public static IAppBuilder UseLinkedInAuthentication(this IAppBuilder app,
            LinkedInAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(LinkedInAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseLinkedInAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseLinkedInAuthentication(new LinkedInAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}