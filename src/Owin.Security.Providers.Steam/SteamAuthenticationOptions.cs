using Microsoft.Owin;
using Owin.Security.Providers.OpenIDBase;

namespace Owin.Security.Providers.Steam
{
    public sealed class SteamAuthenticationOptions : OpenIDAuthenticationOptions
    {
        public string ApplicationKey { get; set; }

        /// <summary>
        /// When enabled, the middleware will query Steam API for user profile and add some useful profile properties to claims.
        /// </summary>
        public bool QueryProfile { get; set; } = true;

        public SteamAuthenticationOptions()
        {
            ProviderDiscoveryUri = "http://steamcommunity.com/openid/";
            Caption = "Steam";
            AuthenticationType = "Steam";
            CallbackPath = new PathString("/signin-openidsteam");
        }
    }
}
