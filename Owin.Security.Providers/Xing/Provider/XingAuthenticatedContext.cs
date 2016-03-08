using System;
using System.Security.Claims;
using Microsoft.Owin.Security.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Xing.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class XingAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="XingAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="id">Xing user ID</param>
        /// <param name="accessToken">Xing access token</param>
        /// <param name="accessTokenSecret">Xing access token secret</param>
        /// <param name="users">The JSON formatted user profiles provided by the API</param>
        public XingAuthenticatedContext(IOwinContext context, string id, string accessToken, string accessTokenSecret, JObject users)
            : base(context)
        {
            Id = id;
            AccessToken = accessToken;
            AccessTokenSecret = accessTokenSecret;

            var usersArray = JArray.Parse(TryGetValue(users, "users"));
            var user = usersArray != null ? JObject.Parse(usersArray[0].ToString()) : null;

            if (user != null)
            {
                User = user;

                Id = TryGetValue(user, "id");
                Gender = TryGetValue(user, "gender");
                FirstName = TryGetValue(user, "first_name");
                LastName = TryGetValue(user, "last_name");
                DisplayName = TryGetValue(user, "display_name");
                Profile = TryGetValue(user, "permalink");
                Email = TryGetValue(user, "active_email");
                DateTime birthdate;
                if (DateTime.TryParse(TryGetValue(user, "birth_date", "day") + "/" + TryGetValue(user, "birth_date", "month") + "/" + TryGetValue(user, "birth_date", "year"), out birthdate))
                    BirthDate = birthdate;
            }
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Xing user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the gender
        /// </summary>
        public string Gender { get; private set; }

        /// <summary>
        /// Gets the first name
        /// </summary>
        public string FirstName { get; private set; }

        /// <summary>
        /// Gets the last name
        /// </summary>
        public string LastName { get; private set; }

        /// <summary>
        /// Gets the display name
        /// </summary>
        public string DisplayName { get; private set; }

        /// <summary>
        /// Gets the permalink to the user profile
        /// </summary>
        public string Profile { get; private set; }

        /// <summary>
        /// Gets the active email
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the active email
        /// </summary>
        public DateTime? BirthDate { get; private set; }

        /// <summary>
        /// Gets the Xing access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Xing access token secret
        /// </summary>
        public string AccessTokenSecret { get; private set; }

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

        // Get the given subProperty from a property.
        private static string TryGetValue(JObject user, string propertyName, params string[] subProperties)
        {
            JToken value;
            if (user.TryGetValue(propertyName, out value))
            {
                foreach (var subProperty in subProperties)
                {
                    var subObject = JObject.Parse(value.ToString());
                    if (!(subObject != null && subObject.TryGetValue(subProperty, out value)))
                    {
                        return null;
                    }
                }
                return value != null ? value.ToString() : null;
            }
            return null;
        }
    }
}