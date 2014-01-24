using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Owin.Security.Providers.GitHub;
using Owin.Security.Providers.LinkedIn;
using Owin.Security.Providers.Yahoo;
using Owin.Security.Providers.OpenID;
using Owin.Security.Providers.Steam;

namespace OwinOAuthProvidersDemo
{
    public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Enable the application to use a cookie to store information for the signed in user
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login")
            });
            // Use a cookie to temporarily store information about a user logging in with a third party login provider
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // Uncomment the following lines to enable logging in with third party login providers
            //app.UseMicrosoftAccountAuthentication(
            //    clientId: "",
            //    clientSecret: "");

            //app.UseTwitterAuthentication(
            //   consumerKey: "",
            //   consumerSecret: "");

            //app.UseFacebookAuthentication(
            //   appId: "",
            //   appSecret: "");

            //app.UseGoogleAuthentication();

            //app.UseLinkedInAuthentication("", "");

            //app.UseYahooAuthentication(
            //    "",
            //    "");

            //app.UseGitHubAuthentication("", "");


            //app.UseOpenIDAuthentication("http://me.yahoo.com/", "Yahoo");

            //app.UseOpenIDAuthentication("https://openid.stackexchange.com/", "StackExchange");

            //app.UseOpenIDAuthentication("https://www.google.com/accounts/o8/id", "Google");

            //app.UseSteamAuthentication(applicationKey: "");

        }
    }
}