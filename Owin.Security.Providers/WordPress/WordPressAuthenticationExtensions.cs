using System;

namespace Owin.Security.Providers.WordPress
{
    public static class WordPressAuthenticationExtensions
    {
        public static IAppBuilder UseWordPressAuthentication(this IAppBuilder app,
            WordPressAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(WordPressAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseWordPressAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseWordPressAuthentication(new WordPressAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}