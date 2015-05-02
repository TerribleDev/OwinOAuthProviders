using System;

namespace Owin.Security.Providers.Untappd
{
    public static class UntappdAuthenticationExtensions
    {
        /// <summary>
        ///  Login with Untappd. http://yourUrl/signin-Untappd will be used as the redirect URI
        /// </summary>
        /// <param name="app"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        public static IAppBuilder UseUntappdAuthentication(this IAppBuilder app,
            UntappdAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(UntappdAuthenticationMiddleware), app, options);

            return app;
        }
        /// <summary>
        /// Login with Untappd. http://yourUrl/signin-Untappd will be used as the redirect URI
        /// </summary>
        /// <param name="app"></param>
        /// <param name="clientId"></param>
        /// <param name="clientSecret"></param>
        /// <returns></returns>
        public static IAppBuilder UseUntappdAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseUntappdAuthentication(new UntappdAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}