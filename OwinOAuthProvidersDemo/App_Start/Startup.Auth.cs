using System;
using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Owin.Security.Providers.ArcGISOnline;
using Owin.Security.Providers.BattleNet;
using Owin.Security.Providers.Buffer;
using Owin.Security.Providers.Dropbox;
using Owin.Security.Providers.GitHub;
using Owin.Security.Providers.GooglePlus;
using Owin.Security.Providers.GooglePlus.Provider;
using Owin.Security.Providers.HealthGraph;
using Owin.Security.Providers.Instagram;
using Owin.Security.Providers.LinkedIn;
using Owin.Security.Providers.Reddit;
using Owin.Security.Providers.Salesforce;
using Owin.Security.Providers.StackExchange;
using Owin.Security.Providers.TripIt;
using Owin.Security.Providers.Yahoo;
using Owin.Security.Providers.OpenID;
using Owin.Security.Providers.Steam;
using Owin.Security.Providers.WordPress;

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

            //app.UseYahooAuthentication("", "");

            //app.UseTripItAuthentication("", "");
            
            //app.UseGitHubAuthentication("", "");

            //app.UseBufferAuthentication("", "");

            //app.UseRedditAuthentication("", "");

            //app.UseStackExchangeAuthentication(
            //    clientId: "",
            //    clientSecret: "",
            //    key: "");

            //app.UseInstagramInAuthentication("", "");

            //var options = new GooglePlusAuthenticationOptions
            //{
            //    ClientId = "",
            //    ClientSecret = "",
            //    RequestOfflineAccess = true,
            //    Provider = new GooglePlusAuthenticationProvider
            //    {
            //        OnAuthenticated = async context => System.Diagnostics.Debug.WriteLine(String.Format("Refresh Token: {0}", context.RefreshToken))
            //    }
            //};
            //options.MomentTypes.Add("http://schemas.google.com/AddActivity");
            //options.MomentTypes.Add("http://schemas.google.com/CheckInActivity");
            //options.MomentTypes.Add("http://schemas.google.com/BuyActivity");
            //app.UseGooglePlusAuthentication(options);


            //app.UseOpenIDAuthentication("http://me.yahoo.com/", "Yahoo");

            //app.UseOpenIDAuthentication("https://openid.stackexchange.com/", "StackExchange");

            //app.UseOpenIDAuthentication("https://www.google.com/accounts/o8/id", "Google");

            //app.UseSteamAuthentication(applicationKey: "");

            //app.UseOpenIDAuthentication("http://orange.fr", "Orange");
            // Use OpenId provider login uri instead of discovery uri
            //app.UseOpenIDAuthentication("http://openid.orange.fr/server", "Orange", true);

            //app.UseSalesforceAuthentication(
            //    clientId: "", 
            //    clientSecret: "");

            //in scenarios where a sandbox URL needs to be used
            //var salesforceOptions = new SalesforceAuthenticationOptions
            //{
            //    Endpoints =
            //        new SalesforceAuthenticationOptions.SalesforceAuthenticationEndpoints
            //        {
            //            AuthorizationEndpoint =
            //                "https://ap1.salesforce.com/services/oauth2/authorize",
            //            TokenEndpoint = "https://ap1.salesforce.com/services/oauth2/token"
            //        },
            //    ClientId = "",
            //    ClientSecret = "",
            //    Provider = new SalesforceAuthenticationProvider()
            //    {
            //        OnAuthenticated = async context =>
            //        {
            //            System.Diagnostics.Debug.WriteLine(context.AccessToken);
            //            System.Diagnostics.Debug.WriteLine(context.RefreshToken);
            //            System.Diagnostics.Debug.WriteLine(context.OrganizationId);
            //        }
            //    }
            //};
            //app.UseSalesforceAuthentication(salesforceOptions);

            //app.UseArcGISOnlineAuthentication(
            //    clientId: "",
            //    clientSecret: "");

            //app.UseWordPressAuthentication(
            //    clientId: "",
            //    clientSecret: "");

            //app.UseDropboxAuthentication(
            //    appKey: "",
            //    appSecret: "");

            //app.UseHealthGraphAuthentication(
            //    clientId: "",
            //    clientSecret: "");


			//app.UseBattleNetAuthentication(new BattleNetAuthenticationOptions
			//{
			//	ClientId = "",
			//	ClientSecret = ""
			//});
			//app.UseBattleNetAuthentication(
			//	clientId: "",
			//	clientSecret: "");
        }
    }
}