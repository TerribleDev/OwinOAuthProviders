namespace Owin.Security.Providers.Shopify
{
    using System;

    public static class ShopifyAuthenticationExtensions
    {
        /// <summary>
        /// Use Shopify Shop OAuth authentication.
        /// </summary>
        /// <param name="app">Instance of <see cref="IAppBuilder"/>.</param>
        /// <param name="options">Shopify overrided authentication options.</param>
        /// <returns>Returns instance of <see cref="IAppBuilder"/>.</returns>
        public static IAppBuilder UseShopifyAuthentication(this IAppBuilder app, ShopifyAuthenticationOptions options)
        {
            if (null == app)
            {
                throw new ArgumentNullException("app");
            }

            if (null == options)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(ShopifyAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Use Shopify Shop OAuth authentication with default authentication options.
        /// </summary>
        /// <param name="app">Instance of <see cref="IAppBuilder"/>.</param>
        /// <param name="apiKey">Shopify App - API key.</param>
        /// <param name="apiSecret">Shopify App - API secret.</param>
        /// <returns>Returns instance of <see cref="IAppBuilder"/>.</returns>
        public static IAppBuilder UseShopifyAuthentication(this IAppBuilder app, string apiKey, string apiSecret)
        {
            return app.UseShopifyAuthentication(new ShopifyAuthenticationOptions
            {
                ApiKey = apiKey,
                ApiSecret = apiSecret
            });
        }
    }
}