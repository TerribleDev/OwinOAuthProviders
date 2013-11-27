using System;

namespace Owin.Security.Providers.GitHub
{
    public static class GitHubAuthenticationExtensions
    {
        public static IAppBuilder UseGitHubAuthentication(this IAppBuilder app,
            GitHubAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(GitHubAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseGitHubAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseGitHubAuthentication(new GitHubAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret
            });
        }
    }
}