using System;

namespace Owin.Security.Providers.Buffer
{
    public static class BufferAuthenticationExtensions
    {
        public static IAppBuilder UseBufferAuthentication(this IAppBuilder app,
            BufferAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(BufferAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseBufferAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseBufferAuthentication(new BufferAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}