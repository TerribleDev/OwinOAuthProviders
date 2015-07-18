using System;
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

        public StravaAuthenticatedContext(  IOwinContext context, 
                                            JObject user, 
                                            string accessToken, 
                                            string tokenType)
                                        : base(context)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            User = user;
            AccessToken = accessToken;
            TokenType = tokenType;

            // There are many other properties Strava provides for
            // authenticated user.  Only the basic are set below,
            // others are ommitted on purpose.
            
            Id = TryGetValue(user, "id"); ;
            if (Id == null)
            {
                throw new ArgumentException("The user does not have an id.", "user");
            }
            DisplayName = TryGetValue(user, "firstname");
            FirstName = TryGetValue(user, "firstname");
            LastName = TryGetValue(user, "lastname");
            Name = FirstName + " " + LastName;
            PhotoMedium = TryGetValue(user, "profile_medium");
            Email = TryGetValue(user, "email"); ;
            Link = string.Format("{0}{1}", UserUrlBase, Id); ;
        }

        /// <summary>
        /// User display name
        /// </summary>
        public string DisplayName { get; set; }

        /// <summary>
        /// Gets the Strava token type
        /// </summary>
        public string TokenType { get; set; }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Strava user
        /// </remarks>
        public JObject User { get; set; }

        public string Id { get; private set; }
        public string FirstName { get; private set; }
        public string LastName { get; private set; }
        public string Name { get; private set; }
        public string Email { get; private set; }
        public string Link { get; private set; }
        public string PhotoMedium { get; private set; }
        
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