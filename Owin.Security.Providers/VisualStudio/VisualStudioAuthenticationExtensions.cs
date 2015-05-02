using System;

namespace Owin.Security.Providers.VisualStudio {
	public static class VisualStudioAuthenticationExtensions {
		public static IAppBuilder UseVisualStudioAuthentication(this IAppBuilder app, VisualStudioAuthenticationOptions options) {
			if (app == null) throw new ArgumentNullException("app");
			if (options == null) throw new ArgumentNullException("options");

			app.Use(typeof(VisualStudioAuthenticationMiddleware), app, options);

			return app;
		}

		public static IAppBuilder UseVisualStudioAuthentication(this IAppBuilder app, string appId, string appSecret) {
			return app.UseVisualStudioAuthentication(new VisualStudioAuthenticationOptions {
				AppId = appId,
				AppSecret = appSecret
			});
		}
	}
}
