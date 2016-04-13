using System;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Foursquare.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class FoursquareAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="FoursquareAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Foursquare Access token</param>
        public FoursquareAuthenticatedContext(IOwinContext context, JObject user, string accessToken)
            : base(context)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            User = user;
            AccessToken = accessToken;

            var userId = User["id"];

            if (userId == null)
            {
                throw new ArgumentException("The user does not have an id.", nameof(user));
            }

            Id = TryGetValue(user, "id");
            FirstName = TryGetValue(user, "firstName");
            LastName = TryGetValue(user, "lastName");
            Name = FirstName + " " + LastName;
            Gender = TryGetValue(user, "gender");
            Photo = (JObject)user["photo"];
            Friends = TryGetValue(user, "friends");
            HomeCity = TryGetValue(user, "homeCity");
            Bio = TryGetValue(user, "bio");
            Contact = (JObject)user["contact"];
            Phone = TryGetValue(Contact, "phone");
            Email = TryGetValue(Contact, "email");
            Twitter = TryGetValue(Contact, "twitter");
            Facebook = TryGetValue(Contact, "facebook");
            Badges = TryGetValue(user, "badges");
            Mayorships = TryGetValue(user, "mayorships");
            Checkins = TryGetValue(user, "checkins");
            Photos = TryGetValue(user, "photos");
            Scores = TryGetValue(user, "scores");
            Link = "https://foursquare.com/user/" + Id;
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Foursquare user obtained from the User Info endpoint https://api.foursquare.com/v2/users/self
        /// </remarks>
        public JObject User { get; }
        /// <summary>
        /// Gets the Foursquare access token
        /// </summary>
        public string AccessToken { get; private set; }
        /// <summary>
        /// Gets the Foursquare user ID
        /// </summary>
        public string Id { get; }
        /// <summary>
        /// Gets the user's first name
        /// </summary>
        public string FirstName { get; }
        /// <summary>
        /// Gets the user's last name
        /// </summary>
        public string LastName { get; }
        /// <summary>
        /// Gets the user's full name
        /// </summary>
        public string Name { get; private set; }
        /// <summary>
        /// Gets the user's gender
        /// </summary>
        public string Gender { get; private set; }
        /// <summary>
        /// Gets the user's photo
        /// </summary>
        public JObject Photo { get; private set; }
        /// <summary>
        /// Gets the user's friends
        /// </summary>
        public string Friends { get; private set; }
        /// <summary>
        /// Gets the user's home city
        /// </summary>
        public string HomeCity { get; private set; }
        /// <summary>
        /// Gets the user's biography
        /// </summary>
        public string Bio { get; private set; }
        /// <summary>
        /// Gets the user's contact
        /// </summary>
        public JObject Contact { get; }
        /// <summary>
        /// Gets the user's phone
        /// </summary>
        public string Phone { get; private set; }
        /// <summary>
        /// Gets the user's email
        /// </summary>
        public string Email { get; private set; }
        /// <summary>
        /// Gets the user's Twitter handle
        /// </summary>
        public string Twitter { get; private set; }
        /// <summary>
        /// Gets the user's Facebook id
        /// </summary>
        public string Facebook { get; private set; }
        /// <summary>
        /// Gets the user's badges
        /// </summary>
        public string Badges { get; private set; }
        /// <summary>
        /// Gets the user's mayorships
        /// </summary>
        public string Mayorships { get; private set; }
        /// <summary>
        /// Gets the user's checkins
        /// </summary>
        public string Checkins { get; private set; }
        /// <summary>
        /// Gets the user's photos
        /// </summary>
        public string Photos { get; private set; }
        /// <summary>
        /// Gets the user's scores
        /// </summary>
        public string Scores { get; private set; }
        /// <summary>
        /// Gets the user's link
        /// </summary>
        public string Link { get; private set; }
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