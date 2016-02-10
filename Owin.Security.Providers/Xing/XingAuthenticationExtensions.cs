using System;

namespace Owin.Security.Providers.Xing
{
    public static class XingAuthenticationExtensions
    {
        public static IAppBuilder UseXingAuthentication(this IAppBuilder app, XingAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(XingAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseXingAuthentication(this IAppBuilder app, string consumerKey, string consumerSecret)
        {
            return app.UseXingAuthentication(new XingAuthenticationOptions
            {
                ConsumerKey = consumerKey,
                ConsumerSecret = consumerSecret
            });
        }
    }
}