using System;

namespace Owin.Security.Providers.Vimeo
{
    public static class VimeoAuthenticationExtensions
    {
        public static IAppBuilder UseVimeoAuthentication(this IAppBuilder app, VimeoAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(VimeoAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseVimeoAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            if (string.IsNullOrEmpty(clientId))
                throw new ArgumentNullException(nameof(clientId));
            if (string.IsNullOrEmpty(clientSecret))
                throw new ArgumentNullException(nameof(clientSecret));
            
            return app.UseVimeoAuthentication(new VimeoAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}