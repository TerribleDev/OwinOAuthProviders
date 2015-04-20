using System;
using Microsoft.Owin;

namespace Owin.Security.Providers.Wargaming
{
    /// <summary>
    ///     Extension methods for using <see cref="WargamingAuthenticationMiddleware" />
    /// </summary>
    public static class WargamingAccountAuthenticationExtensions
    {
        private static string ResolveRegionDiscoveryUri(WargamingAuthenticationOptions.Region region)
        {
            switch (region)
            {
                case WargamingAuthenticationOptions.Region.NorthAmerica:
                    return Constants.ProviderDiscoveryUriNorthAmerica;
                case WargamingAuthenticationOptions.Region.Europe:
                    return Constants.ProviderDiscoveryUriEurope;
                case WargamingAuthenticationOptions.Region.Russia:
                    return Constants.ProviderDiscoveryUriRussia;
                case WargamingAuthenticationOptions.Region.Asia:
                    return Constants.ProviderDiscoveryUriAsia;
                case WargamingAuthenticationOptions.Region.Korea:
                    return Constants.ProviderDiscoveryUriKorea;
                default:
                    return Constants.ProviderDiscoveryUriNorthAmerica;
            }
        }

        /// <summary>
        ///     Authenticate users using Wargaming
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder" /> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder" /></returns>
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

            return app.Use(typeof (WargamingAuthenticationMiddleware), app, options);
        }

        /// <summary>
        ///     Authenticate users using Steam
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder" /> passed to the configuration method</param>
        /// <param name="appId">The wargaming application ID</param>
        /// <param name="region">The <see cref="WargamingAuthenticationOptions.Region" /> to authenticate</param>
        /// <returns>The updated <see cref="IAppBuilder" /></returns>
        public static IAppBuilder UseWargamingAccountAuthentication(this IAppBuilder app, string appId, WargamingAuthenticationOptions.Region region = WargamingAuthenticationOptions.Region.NorthAmerica)
        {
            return UseWargamingAccountAuthentication(app, new WargamingAuthenticationOptions
            {
                ProviderDiscoveryUri = ResolveRegionDiscoveryUri(region),
                Caption = "Wargaming",
                AuthenticationType = "Wargaming",
                CallbackPath = new PathString("/signin-wargaming"),
                AppId = appId
            });
        }
    }
}