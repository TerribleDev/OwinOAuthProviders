using System;

namespace Owin.Security.Providers.Onshape
{
    public static class OnshapeAuthenticationExtensions
    {
        public static IAppBuilder UseOnshapeAuthentication(this IAppBuilder app,
            OnshapeAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(OnshapeAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseOnshapeAuthentication(this IAppBuilder app, string appKey, 
          string appSecret)
        {
            return app.UseOnshapeAuthentication(new OnshapeAuthenticationOptions
            {
                AppKey = appKey,
                AppSecret = appSecret                
            });
        }
    }
}