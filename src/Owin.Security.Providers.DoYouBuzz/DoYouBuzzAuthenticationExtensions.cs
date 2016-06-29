using System;

namespace Owin.Security.Providers.DoYouBuzz
{
    public static class DoYouBuzzAuthenticationExtensions
    {
        public static IAppBuilder UseDoYouBuzzAuthentication(this IAppBuilder app, DoYouBuzzAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(DoYouBuzzAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseDoYouBuzzAuthentication(this IAppBuilder app, string consumerKey, string consumerSecret)
        {
            return app.UseDoYouBuzzAuthentication(new DoYouBuzzAuthenticationOptions
            {
                ConsumerKey = consumerKey,
                ConsumerSecret = consumerSecret
            });
        }
    }
}