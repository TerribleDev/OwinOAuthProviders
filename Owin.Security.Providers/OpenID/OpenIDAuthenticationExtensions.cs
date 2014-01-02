using Microsoft.Owin;
using System;

namespace Owin.Security.Providers.OpenID
{
    /// <summary>
    /// Extension methods for using <see cref="OpenIDAuthenticationMiddleware"/>
    /// </summary>
    public static class OpenIDAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using an OpenID provider
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseOpenIDAuthentication(this IAppBuilder app, OpenIDAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(OpenIDAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using an OpenID provider
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="providerUri">The uri of the OpenID provider</param>
        /// <param name="providerName">Name of the OpenID provider</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseOpenIDAuthentication(this IAppBuilder app, string providerUri, string providerName)
        {
            return UseOpenIDAuthentication(app, new OpenIDAuthenticationOptions
            {
                ProviderDiscoveryUri = providerUri,
                Caption = providerName,
                AuthenticationType = providerName,
                CallbackPath = new PathString("/signin-openid" + providerName.ToLowerInvariant())
            });
        }
    }
}
