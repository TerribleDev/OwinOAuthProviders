using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.SoundCloud.Provider
{
    /// <summary>
    ///     Contains information about the login session as well as the user
    ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
    /// </summary>
    public class SoundCloudAuthenticatedContext : BaseContext
    {
        public SoundCloudAuthenticatedContext(IOwinContext context, JObject user, string accessToken)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;

            Id = TryGetValue(user, "id");
            UserName = TryGetValue(user, "username");
        }

        /// <summary>
        ///     Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        ///     Contains the SoundCloud user obtained from the endpoint https://api.soundcloud.com/me
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        ///     Gets the SoundCloud access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        ///     Gets the SoundCloud user ID
        /// </summary>
        public string Id { get; set; }

        /// <summary>
        ///     Gets the SoundCloud username
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        ///     Gets the <see cref="ClaimsIdentity" /> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        ///     Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}