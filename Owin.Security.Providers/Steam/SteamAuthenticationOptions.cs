using Owin.Security.Providers.OpenID;

namespace Owin.Security.Providers.Steam
{
    public sealed class SteamAuthenticationOptions : OpenIDAuthenticationOptions
    {
        public string ApplicationKey { get; set; }
    }
}
