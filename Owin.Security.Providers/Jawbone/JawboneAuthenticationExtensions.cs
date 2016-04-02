using System;
using Microsoft.Owin;

namespace Owin.Security.Providers.Jawbone
{
    public static class JawboneAuthenticationExtensions
    {
        public static IAppBuilder UseJawboneAuthentication(this IAppBuilder app,
            JawboneAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(JawboneAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseJawboneAuthentication(this IAppBuilder app, string appKey,
          string appSecret)
        {
            return app.UseJawboneAuthentication(new JawboneAuthenticationOptions
            {
                AppKey = appKey,
                AppSecret = appSecret
            });
        }
    }
}
