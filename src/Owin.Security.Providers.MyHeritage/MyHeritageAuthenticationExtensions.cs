using System;

namespace Owin.Security.Providers.MyHeritage
{
    public static class MyHeritageAuthenticationExtensions
    {
        public static IAppBuilder UseMyHeritageAuthentication(this IAppBuilder app,
            MyHeritageAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(MyHeritageAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseMyHeritageAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseMyHeritageAuthentication(new MyHeritageAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}