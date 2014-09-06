// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;

namespace Owin.Security.Providers.TripIt
{
    /// <summary>
    /// Extension methods for using <see cref="TripItAuthenticationMiddleware"/>
    /// </summary>
    public static class TripItAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using TripIt
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseTripItAuthentication(this IAppBuilder app, TripItAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(TripItAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using TripIt
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="consumerKey">The TripIt-issued consumer key</param>
        /// <param name="consumerSecret">The TripIt-issued consumer secret</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseTripItAuthentication(
            this IAppBuilder app,
            string consumerKey,
            string consumerSecret)
        {
            return UseTripItAuthentication(
                app,
                new TripItAuthenticationOptions
                {
                    ConsumerKey = consumerKey,
                    ConsumerSecret = consumerSecret,
                });
        }
    }
}
