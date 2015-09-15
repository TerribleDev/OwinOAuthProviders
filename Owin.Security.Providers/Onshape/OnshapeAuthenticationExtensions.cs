using Microsoft.Owin;
using System;

namespace Owin.Security.Providers.Onshape
{
    public static class OnshapeAuthenticationExtensions
    {
        public static IAppBuilder UseOnshapeAuthentication(this IAppBuilder app,
            OnshapeAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(OnshapeAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseOnshapeAuthentication(this IAppBuilder app, string appKey, 
          string appSecret, string callbackPath)
        {
            return app.UseOnshapeAuthentication(new OnshapeAuthenticationOptions
            {
                AppKey = appKey,
                AppSecret = appSecret,
                CallbackPath = new PathString(callbackPath)
            });
        }

        public static IAppBuilder UseOnshapeAuthentication(this IAppBuilder app, string appKey,
          string appSecret, string callbackPath, string hostname)
        {
          return app.UseOnshapeAuthentication(new OnshapeAuthenticationOptions
          {
            AppKey = appKey,
            AppSecret = appSecret,
            CallbackPath = new PathString(callbackPath),
            Hostname = hostname
          });
        }
    }
}