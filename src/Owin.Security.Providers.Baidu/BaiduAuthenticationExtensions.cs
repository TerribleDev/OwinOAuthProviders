using System;

namespace Owin.Security.Providers.Baidu
{
    public static class BaiduAuthenticationExtensions
    {
        public static IAppBuilder UseBaiduAuthentication(this IAppBuilder app,
            BaiduAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(BaiduAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseBaiduAuthentication(this IAppBuilder app, string apiKey, string secretKey)
        {
            return app.UseBaiduAuthentication(new BaiduAuthenticationOptions
            {
                ApiKey = apiKey,
                SecretKey = secretKey
            });
        }
    }
}