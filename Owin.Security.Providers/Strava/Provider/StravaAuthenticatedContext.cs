using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Strava.Provider
{
    public class StravaAuthenticatedContext : BaseContext
    {
        private const string UserUrlBase = "https://www.strava.com/athletes/";

        public StravaAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string tokenType)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
            TokenType = tokenType;

            UserId = TryGetValue(user, "id");
            UserUrl = string.Format("{0}{1}", UserUrlBase, UserId);
            Username = TryGetValue(user, "email");
            UserDisplayName = TryGetValue(user, "firstname") + " " + TryGetValue(user, "lastname");
            UserAvatarUrlMedium = TryGetValue(user, "profile");
            UserAvatarUrlSmall = TryGetValue(user, "profile_medium");

        }

        /// <summary>
        /// URL to the medium size avatar
        /// </summary>
        public string UserAvatarUrlMedium { get; set; }

        /// <summary>
        /// URL to the small size avatar
        /// </summary>
        public string UserAvatarUrlSmall { get; set; }

        /// <summary>
        /// URL to the user
        /// </summary>
        public string UserUrl { get; set; }

        /// <summary>
        /// User display name
        /// </summary>
        public string UserDisplayName { get; set; }

        /// <summary>
        /// Username
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// User unique ID
        /// </summary>
        public string UserId { get; set; }

        /// <summary>
        /// Gets the Gitter token type
        /// </summary>
        public string TokenType { get; set; }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Gitter user
        /// </remarks>
        public JObject User { get; set; }

        /// <summary>
        /// Gets the Gitter access token
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