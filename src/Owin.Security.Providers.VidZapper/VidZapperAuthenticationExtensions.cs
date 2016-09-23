using System;

namespace Owin.Security.Providers.VidZapper
{
    public static class VidZapperAuthenticationExtensions
    {
        public static IAppBuilder UseVidZapperAuthentication(this IAppBuilder app,
            VidZapperAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(VidZapperAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseVidZapperAuthentication(this IAppBuilder app, string clientId, string clientSecret,string host="live.vzconsole.com")
        {
            return app.UseVidZapperAuthentication(new VidZapperAuthenticationOptions
            {
                ApiKey = clientId,
                Secret = clientSecret,
                Host = host
            });
        }
    }
}