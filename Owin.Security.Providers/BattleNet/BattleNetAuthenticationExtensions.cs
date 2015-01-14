using System;

namespace Owin.Security.Providers.BattleNet
{
	public static class BattleNetAuthenticationExtensions
	{

		public static IAppBuilder UseBattleNetAuthentication(this IAppBuilder app, BattleNetAuthenticationOptions options)
		{
			if (app == null)
				throw new ArgumentException("app");
			if (options == null)
				throw new ArgumentException("options");

			app.Use(typeof(BattleNetAuthenticationMiddleware), app, options);

			return app;
		}
		public static IAppBuilder UseBattleNetAuthentication(this IAppBuilder app, string clientId, string clientSecret)
		{
			return app.UseBattleNetAuthentication(new BattleNetAuthenticationOptions
			{
				ClientId = clientId,
				ClientSecret = clientSecret,
				Region = Region.US
			});
		}
	}
}
