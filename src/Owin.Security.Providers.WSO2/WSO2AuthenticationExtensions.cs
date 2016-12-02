using Microsoft.Owin;
using Owin;
using System;

namespace Owin.Security.Providers.WSO2
{
    public static class WSO2AuthenticationExtensions
	{
		public static IAppBuilder UseWSO2Authentication(this IAppBuilder app, WSO2AuthenticationOptions options)
		{
			if (app == null)
				throw new ArgumentNullException(nameof(app));
			if (options == null)
				throw new ArgumentNullException(nameof(options));

			app.Use(typeof(WSO2AuthenticationMiddleware), app, options);

			return app;
		}

		public static IAppBuilder UseWSO2Authentication(this IAppBuilder app, string baseUrl, string clientId, string clientSecret)
		{
			return app.UseWSO2Authentication(new WSO2AuthenticationOptions
			{
				BaseUrl = baseUrl,
				ClientId = clientId,
				ClientSecret = clientSecret
			});
		}
	}
}
