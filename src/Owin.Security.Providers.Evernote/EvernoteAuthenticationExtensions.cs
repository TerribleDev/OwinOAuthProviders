using System;

namespace Owin.Security.Providers.Evernote
{
    public static class EvernoteAuthenticationExtensions
    {
        public static IAppBuilder UseEvernoteAuthentication(this IAppBuilder app,
            EvernoteAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(EvernoteAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseEvernoteAuthentication(this IAppBuilder app, string appKey, string appSecret)
        {
            return app.UseEvernoteAuthentication(new EvernoteAuthenticationOptions
            {
                AppKey = appKey,
                AppSecret = appSecret
            });
        }
    }
}