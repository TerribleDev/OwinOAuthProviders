using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Instagram.Provider
{
    public class InstagramAuthenticatedContext
    {
        

        public InstagramAuthenticatedContext(IOwinContext context, JObject user, string accessToken)
        {
            User = user;
            AccessToken = accessToken;

            Id = TryGetValue(user, "id");
            Name = TryGetValue(user, "full_name");
            UserName = TryGetValue(user, "username");
            ProfilePicture = TryGetValue(user, "profile_picture");
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Instagram user obtained from token ednpoint
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Instagram access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Instagram user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the Instagram username
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the Instagram users profile picture
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
    }
}