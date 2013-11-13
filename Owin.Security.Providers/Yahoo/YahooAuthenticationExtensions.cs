// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;

namespace Owin.Security.Providers.Yahoo
{
    /// <summary>
    /// Extension methods for using <see cref="YahooAuthenticationMiddleware"/>
    /// </summary>
    public static class YahooAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using Yahoo
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseYahooAuthentication(this IAppBuilder app, YahooAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(YahooAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using Yahoo
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="consumerKey">The Yahoo-issued consumer key</param>
        /// <param name="consumerSecret">The Yahoo-issued consumer secret</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseYahooAuthentication(
            this IAppBuilder app,
            string consumerKey,
            string consumerSecret)
        {
            return UseYahooAuthentication(
                app,
                new YahooAuthenticationOptions
                {
                    ConsumerKey = consumerKey,
                    ConsumerSecret = consumerSecret,
                });
        }
    }
}
