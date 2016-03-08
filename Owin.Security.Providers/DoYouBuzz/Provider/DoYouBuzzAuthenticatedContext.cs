using System.Security.Claims;
using Microsoft.Owin.Security.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.DoYouBuzz
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class DoYouBuzzAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="DoYouBuzzAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="id">DoYouBuzz user ID</param>
        /// <param name="accessToken">DoYouBuzz access token</param>
        /// <param name="accessTokenSecret">DoYouBuzz access token secret</param>
        /// <param name="user">The JSON formatted user profile provided by the API</param>
        public DoYouBuzzAuthenticatedContext(IOwinContext context, string id, string accessToken, string accessTokenSecret, JObject user)
            : base(context)
        {
            User = user;

            Id = TryGetValue(user, "user", "id");
            FirstName = TryGetValue(user, "user", "firstname");
            LastName = TryGetValue(user, "user", "lastname");
            Profile = TryGetValue(user, "user", "slug");
            Email = TryGetValue(user, "user", "email");
            AccessToken = accessToken;
            AccessTokenSecret = accessTokenSecret;
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the DoYouBuzz user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the first name
        /// </summary>
        public string FirstName { get; private set; }

        /// <summary>
        /// Gets the last name
        /// </summary>
        public string LastName { get; private set; }

        /// <summary>
        /// Gets the permalink to the user profile
        /// </summary>
        public string Profile { get; private set; }

        /// <summary>
        /// Gets the active email
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the DoYouBuzz access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the DoYouBuzz access token secret
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
        private static string TryGetValue(JObject user, string propertyName, string subProperty)
        {
            JToken value;
            if (user.TryGetValue(propertyName, out value))
            {
                var subObject = JObject.Parse(value.ToString());
                if (subObject != null && subObject.TryGetValue(subProperty, out value))
                {
                    return value.ToString();
                }
            }
            return null;
        }

        // Get the given subProperty from a list property.
        private static string TryGetFirstValue(JObject user, string propertyName, string subProperty)
        {
            JToken value;
            if (user.TryGetValue(propertyName, out value))
            {
                var array = JArray.Parse(value.ToString());
                if (array != null && array.Count > 0)
                {
                    var subObject = JObject.Parse(array.First.ToString());
                    if (subObject != null)
                    {
                        if (subObject.TryGetValue(subProperty, out value))
                        {
                            return value.ToString();
                        }
                    }
                }
            }
            return null;
        }
    }
}