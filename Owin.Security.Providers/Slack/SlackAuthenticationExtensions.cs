using System;

namespace Owin.Security.Providers.Slack
{
    public static class SlackAuthenticationExtensions
    {
        public static IAppBuilder UseSlackAuthentication(this IAppBuilder app, SlackAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(SlackAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseSlackAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseSlackAuthentication(new SlackAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
            });
        }
    }
}
