using System;

namespace Owin.Security.Providers.Flickr
{
    public static class FlickrAuthenticationExtensions
    {
        public static IAppBuilder UseFlickrAuthentication(this IAppBuilder app,
            FlickrAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(FlickrAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseFlickrAuthentication(this IAppBuilder app, string appKey, string appSecret)
        {
            return app.UseFlickrAuthentication(new FlickrAuthenticationOptions
            {
                AppKey = appKey,
                AppSecret = appSecret
            });
        }
    }
}