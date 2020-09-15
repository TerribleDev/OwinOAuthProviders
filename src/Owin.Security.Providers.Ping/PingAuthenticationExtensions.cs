namespace Owin.Security.Providers.Ping
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    public static class PingAuthenticationExtensions
    {
        public static IAppBuilder UsePingAuthentication(this IAppBuilder app, PingAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException(nameof(app));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            app.Use(typeof(PingAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UsePingAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UsePingAuthentication(new PingAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }

        /// <summary>The to query string.</summary>
        /// <param name="parameters">The parameters.</param>
        /// <returns>The <see cref="string"/>.</returns>
        /// <exception cref="ArgumentNullException">If the parameters are null</exception>
        public static string ToQueryString(this Dictionary<string, string> parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException("parameters");
            }

            // Avoiding URL encoding the query string parameters as it is NOT compatible with Ping Federate.
            var query = string.Join("&", parameters.Where(pair => !string.IsNullOrEmpty(pair.Value)).Select(item => string.Format(CultureInfo.InvariantCulture, "{0}={1}", item.Key, item.Value)).ToArray());
            return string.IsNullOrEmpty(query) ? string.Empty : "?" + query;
        }
    }
}
