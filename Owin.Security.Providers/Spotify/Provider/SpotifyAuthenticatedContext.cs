using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System;
using System.Globalization;
using System.Security.Claims;

namespace Owin.Security.Providers.Spotify.Provider
{
    public class SpotifyAuthenticatedContext: BaseContext
    {
        public SpotifyAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string refreshToken, string expiresIn)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            int expiresValue;
            if (Int32.TryParse(expiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            Id = TryGetValue(user, "id");
            Name = TryGetValue(user, "display_name");

            ProfilePicture = TryGetListValue(user, "images", 0, "url");
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Spotify user obtained from token ednpoint
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Spotify access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets Spotify refresh token
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets Spotify access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the Spotify user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the Spotify users profile picture
        /// </summary>
        public string ProfilePicture { get; private set; }

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

        private static string TryGetListValue(JObject user, string listPropertyName, int listPosition, string listEntryPropertyName)
        {
            JToken listValue;
            bool valueExists = user.TryGetValue(listPropertyName, out listValue);
            if (!valueExists) return null;
            JArray list = (JArray)listValue;
            
            if (list.Count <= listPosition) return null;
            JToken entry = list[listPosition];

            return entry.Value<string>(listEntryPropertyName);
        }
    }
}