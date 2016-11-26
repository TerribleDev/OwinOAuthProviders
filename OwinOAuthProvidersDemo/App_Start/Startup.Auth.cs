using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Owin.Security.Providers.FreeConferenceCall;
using Owin.Security.Providers.GitHub;

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
            //app.UseDeviantArtAuthentication("id", "secret");
            //app.UseUntappdAuthentication("id", "secret");
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
            app.UseGitHubAuthentication("github client_id here", "github client_secret here");
            app.UseFreeConferenceCallAuthentication("fcc client_id here", "fcc client_secret here");

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

            /*
             * Twitch sign-ins use /signin-Twitch as the URL for authentication
             *

             */

            ////Simple Twitch Sign-in
            //app.UseTwitchAuthentication("", "");

            ////More complex Twitch Sign-in
            //var opt = new TwitchAuthenticationOptions()
            //{
            //    ClientId = "",
            //    ClientSecret = "",
            //    Provider = new TwitchAuthenticationProvider()
            //    {
            //        OnAuthenticated = async z =>
            //        {
            ////            Getting the twitch users picture
            //            z.Identity.AddClaim(new Claim("Picture", z.User.GetValue("logo").ToString()));
            //        }
            ////    You should be able to access these claims with  HttpContext.GetOwinContext().Authentication.GetExternalLoginInfoAsync().Claims in your Account Controller
            //        //    Commonly used in the ExternalLoginCallback() in AccountController.cs
            //        /*

            //           if (user != null)
            //                {
            //                    var claim = (await AuthenticationManager.GetExternalLoginInfoAsync()).ExternalIdentity.Claims.First(
            //                    a => a.Type == "Picture");
            //                    user.Claims.Add(new IdentityUserClaim() { ClaimType = claim.Type, ClaimValue = claim.Value });
            //                    await SignInAsync(user, isPersistent: false);
            //                    return RedirectToLocal(returnUrl);
            //                }
            //         */
            //    }
            //};
            //app.UseTwitchAuthentication(opt);

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

            ////app.UseShopifyAuthentication("", "");

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

            //app.UseBoxAuthentication(
            //    appKey: "",
            //    appSecret: "");

            //app.UseBaiduAuthentication(
            //    apiKey: "",
            //    secretKey: "");

            //app.UseBattleNetAuthentication(new BattleNetAuthenticationOptions
            //{
            //	ClientId = "",
            //	ClientSecret = ""
            //});
            //app.UseBattleNetAuthentication(
            //	clientId: "",
            //	clientSecret: "");

            //app.UseAsanaAuthentication("", "");

            //app.UseEveOnlineAuthentication("", "");

            //app.UseSoundCloudAuthentication("", "");

            //app.UseFoursquareAuthentication(
            //	clientId: "",
            //	clientSecret: "");

            //app.UsePayPalAuthentication(
            //	clientId: "",
            //	clientSecret: "",
            //	isSandbox: false);

            //app.UseWargamingAccountAuthentication("", WargamingAuthenticationOptions.Region.NorthAmerica);

            //app.UseFlickrAuthentication("", "");
            //app.UseVisualStudioAuthentication(
            //	appId: "",
            //	appSecret: "");

            //app.UseSpotifyAuthentication(
            //    clientId: "",
            //    clientSecret: "");

            //var options = new SlackAuthenticationOptions
            //{
            //    ClientId = "",
            //    ClientSecret = "",
            //    TeamId = "" // optional
            //};
            //options.Scope.Add("identify");
            //app.UseSlackAuthentication(options);

            //app.UseGitterAuthentication(
            //    clientId: "",
            //    clientSecret: ""
            //);

            //app.UseImgurAuthentication(
            //    new ImgurAuthenticationOptions
            //    {
            //        ClientId = "",
            //        ClientSecret = ""
            //    });

            //var options = new BacklogAuthenticationOptions
            //{
            //    ClientId = "",
            //    ClientSecret = "",
            //    ContractName = "",
            //    CallbackPath = new PathString(""),  // ex.new PathString("/OauthTokenRequest")
            //    Provider = new BacklogAuthenticationProvider
            //    {
            //        OnAuthenticated = async context => await System.Threading.Tasks.Task.Run(()=> { System.Diagnostics.Debug.WriteLine(String.Format("Refresh Token: {0}", context.RefreshToken)); })
            //    }
            //};

            //app.UseBacklogAuthentication(options);

            //var cosignOptions = new CosignAuthenticationOptions
            //{
            //    AuthenticationType = "Cosign",
            //    SignInAsAuthenticationType = signInAsType,
            //    CosignServer = "weblogin.umich.edu",
            //    CosignServicePort = 6663,
            //    IdentityServerHostInstance = "core1",
            //    ClientServer = "cosignservername"
            //};
            //app.UseCosignAuthentication(cosignOptions);

            //app.UseVimeoAuthentication("", "");

            //app.UseFitbitAuthentication(new FitbitAuthenticationOptions
            //{
            //    ClientId = "",
            //    ClientSecret = ""
            //});

            //app.UseOnshapeAuthentication(
            //    appKey: "",
            //    appSecret: "");
            //
            //
            //app.UseOnshapeAuthentication(new OnshapeAuthenticationOptions()
            //{
            //  AppKey = "",
            //  AppSecret = "",
            //  CallbackPath = new PathString("/oauthRedirect"),
            //  Hostname = "partner.dev.onshape.com"
            //});

            //app.UseVKontakteAuthentication("", "");

            //app.UseXingAuthentication("", "");

            //app.UseDoYouBuzzAuthentication("", "");
            //app.("", "");
            //app.UseOrcidAuthentication("","");

            //app.UseDiscordAuthentication("", "");
            //app.UseGeniAuthentication("", "");
            //app.UseMyHeritageAuthentication("", "");
        }
    }
}