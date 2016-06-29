using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.HealthGraph.Provider
{
    public class HealthGraphAuthenticatedContext : BaseContext
    {
        public HealthGraphAuthenticatedContext(IOwinContext context,
            JObject user,
            JObject profile,
            string accessToken) : base(context)
        {
            User = user;
            Profile = profile;
            AccessToken = accessToken;

            UserId = TryGetValue(user, "userID");
            Name = TryGetValue(profile, "name");
        }

        public JObject Profile { get; set; }

        public JObject User { get; set; }

        public string UserId { get; set; }

        public string Name { get; set; }

        public string AccessToken { get; set; }

        public ClaimsIdentity Identity { get; set; }

        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}