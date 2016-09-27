using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System;
using System.Globalization;
using System.Runtime.Remoting;
using System.Security.Claims;

namespace Owin.Security.Providers.VidZapper.Provider
{
    public class VidZapperAuthenticatedContext: BaseContext
    {
        public VidZapperAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string refreshToken, string expiresIn)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            int expiresValue;
            if (int.TryParse(expiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            Id = TryGetValue(user, "Id");
            Name = TryGetValue(user, "Name");
            Username = TryGetValue(user, "Username");
            Picture = TryGetValue(user, "Picture");
            Email = TryGetValue(user, "Email");
            FirstName = TryGetValue(user, "FirstName");
            LastName = TryGetValue(user, "LastName");
            City = TryGetValue(user, "City");
            Url = TryGetValue(user, "Url");
            LanguageId = TryGetLong(user, "LanguageId");
            ClientId = TryGetLong(user, "ClientId");
        }

        public string Username { get; set; }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the VidZapper user obtained from token ednpoint
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the VidZapper access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets VidZapper refresh token
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets VidZapper access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the VidZapper user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the VidZapper client ID
        /// </summary>
        public long? ClientId { get; private set; }

        /// <summary>
        /// Gets the VidZapper City
        /// </summary>
        public string City { get; private set; }

        /// <summary>
        /// Gets the VidZapper languageID
        /// </summary>
        public long? LanguageId { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string FirstName { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string LastName { get; private set; }

        /// <summary>
        /// Gets the user's email
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the user's url
        /// </summary>
        public string Url { get; private set; }

        /// <summary>
        /// Gets the VidZapper users profile picture
        /// </summary>
        public string Picture { get; private set; }

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

        private static long? TryGetLong(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? long.Parse(value.ToString()) : (long?)null;
        }

        private static string TryGetListValue(JObject user, string listPropertyName, int listPosition, string listEntryPropertyName)
        {
            JToken listValue;
            var valueExists = user.TryGetValue(listPropertyName, out listValue);
            if (!valueExists) return null;
            var list = (JArray)listValue;
            
            if (list.Count <= listPosition) return null;
            var entry = list[listPosition];

            return entry.Value<string>(listEntryPropertyName);
        }
    }
}