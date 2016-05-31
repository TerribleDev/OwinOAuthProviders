using System;

namespace Owin.Security.Providers.Dropbox
{
    public static class DropboxAuthenticationExtensions
    {
        public static IAppBuilder UseDropboxAuthentication(this IAppBuilder app,
            DropboxAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(DropboxAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseDropboxAuthentication(this IAppBuilder app, string appKey, string appSecret)
        {
            return app.UseDropboxAuthentication(new DropboxAuthenticationOptions
            {
                AppKey = appKey,
                AppSecret = appSecret
            });
        }
    }
}