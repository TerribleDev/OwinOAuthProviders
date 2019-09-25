using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.Strava.Provider
{
    public class StravaApplyRedirectContext : BaseContext<StravaAuthenticationOptions>
    {
        public string RedirectUri { get; private set; }
        public AuthenticationProperties Properties { get; private set; }

        public StravaApplyRedirectContext(IOwinContext context, StravaAuthenticationOptions options, AuthenticationProperties properties, string redirectUri) : base(context, options)
        {
            RedirectUri = redirectUri;
            Properties = properties;
        }

       
        
    }
}
