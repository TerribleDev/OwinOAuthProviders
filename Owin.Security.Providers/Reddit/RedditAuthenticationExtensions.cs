using System;

namespace Owin.Security.Providers.Reddit
{
    public static class RedditAuthenticationExtensions
    {
        public static IAppBuilder UseRedditAuthentication(this IAppBuilder app,
            RedditAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(RedditAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseRedditAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseRedditAuthentication(new RedditAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}