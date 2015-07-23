using System;

namespace Owin.Security.Providers.Backlog
{
    public static class BacklogAuthenticationExtensions
    {
        public static IAppBuilder UseBacklogAuthentication(this IAppBuilder app,
            BacklogAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(BacklogAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseBacklogAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseBacklogAuthentication(new BacklogAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}