using Microsoft.Owin.Security.Provider;
using System.Security.Claims;
using Microsoft.Owin;
using Newtonsoft.Json.Linq;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.WSO2
{
    public class WSO2AuthenticatedContext : BaseContext
    {
        public WSO2AuthenticatedContext(IOwinContext context, JObject user, string accessToken)
        : base(context)
        {
            User = user;
            AccessToken = accessToken;

            Id = TryGetValue(user, "sub");
        }

        /// <summary>
        /// Gets the WSO2 user
        /// </summary>
        public JObject User { get; private set; }

        public string Id { get; private set;}

        /// <summary>
        /// Gets the access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }        
    }
}