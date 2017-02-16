using System;

namespace Owin.Security.Providers.WSO2
{
    /// <summary>
    /// Extension methods for using <see cref="WSO2AuthenticationMiddleware"/>
    /// </summary>	
    public static class WSO2AuthenticationExtensions
	{
        /// <summary>
        /// Authenticate users using WSO2 OAuth 2.0
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
		public static IAppBuilder UseWSO2Authentication(this IAppBuilder app, WSO2AuthenticationOptions options)
		{
			if (app == null)
				throw new ArgumentNullException(nameof(app));
			if (options == null)
				throw new ArgumentNullException(nameof(options));

			app.Use(typeof(WSO2AuthenticationMiddleware), app, options);

			return app;
		}

        /// <summary>
        /// Authenticate users using WSO2 OAuth 2.0
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
		/// <param name="baseUrl">The WSO2 Identity Server base url, should be like https://localhost:9443/</param>
        /// <param name="clientId">The WSO2 assigned client id</param>
        /// <param name="clientSecret">The WSO2 assigned client secret</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>		
		public static IAppBuilder UseWSO2Authentication(this IAppBuilder app, string baseUrl, string clientId, string clientSecret)
		{
			return app.UseWSO2Authentication(new WSO2AuthenticationOptions
			{
				BaseUrl = baseUrl.TrimEnd('/') + "/",
				ClientId = clientId,
				ClientSecret = clientSecret
			});
		}
	}
}
