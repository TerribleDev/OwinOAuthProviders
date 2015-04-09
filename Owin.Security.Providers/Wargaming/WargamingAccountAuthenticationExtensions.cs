using Microsoft.Owin;
using System;

namespace Owin.Security.Providers.Wargaming
{
    /// <summary>
    /// Extension methods for using <see cref="WargamingAuthenticationMiddleware"/>
    /// </summary>
    public static class WargamingAccountAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using Wargaming
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseWargamingAccountAuthentication(this IAppBuilder app, WargamingAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            return app.Use(typeof(WargamingAuthenticationMiddleware), app, options);
        }

        /// <summary>
        /// Authenticate users using Steam
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="applicationKey">The wargaming application key</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseWargamingAccountAuthentication(this IAppBuilder app, string appId)
        {
            return UseWargamingAccountAuthentication(app, new WargamingAuthenticationOptions
            {
                ProviderDiscoveryUri = "https://na.wargaming.net/id/openid/",
                Caption = "Wargaming",
                AuthenticationType = "Wargaming",
                CallbackPath = new PathString("/signin-wargaming"),
                AppId = appId
            });
        }
    }
}