using System;

namespace Owin.Security.Providers.Bitbucket
{
    public static class BitbucketAuthenticationExtensions
    {
        public static IAppBuilder UseBitbucketAuthentication(this IAppBuilder app,
            BitbucketAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(BitbucketAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseBitbucketAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseBitbucketAuthentication(new BitbucketAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}