
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Owin.Security.Providers.Strava
{
    public static class StravaAuthenticationExtensions
    {
        
        public static IAppBuilder UseStravaAccountAuthentication(this IAppBuilder app, StravaAuthenticationOptions options)
        {
            if(app == null)
            {
                throw new ArgumentNullException("app is null");
            }
            if(options == null)
            {
                throw new ArgumentNullException("option");
            }

            app.Use(typeof(StravaAuthenticationMiddleware), app, options);
            return app;
        }

        public static IAppBuilder UseStravaAccountAuthentication(this IAppBuilder app, string clientId, string clientSecret, IList<string> scope)
        {
            return UseStravaAccountAuthentication(app,
                new StravaAuthenticationOptions
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret,
                    Scope = scope
                });
        }

    }
}