using Microsoft.Owin;
using Owin.Security.Providers.OpenID;

namespace Owin.Security.Providers.Steam
{
    public sealed class SteamAuthenticationOptions : OpenIDAuthenticationOptions
    {
        public string ApplicationKey { get; set; }

        public SteamAuthenticationOptions()
        {
            ProviderDiscoveryUri = "http://steamcommunity.com/openid/";
            Caption = "Steam";
            AuthenticationType = "Steam";
            CallbackPath = new PathString("/signin-openidsteam");
        }
    }
}
