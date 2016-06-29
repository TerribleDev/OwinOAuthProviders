// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;

namespace Owin.Security.Providers.LinkedIn
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class LinkedInAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="LinkedInAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">LinkedIn Access token</param>
        /// <param name="expires">Seconds until expiration</param>
        public LinkedInAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string expires)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;

            int expiresValue;
            if (int.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            Id = TryGetValue(user, "id");
            Name = TryGetValue(user, "formattedName");
            FamilyName = TryGetValue(user, "lastName");
            GivenName = TryGetValue(user, "firstName");
            Link = TryGetValue(user, "publicProfileUrl");
            UserName = TryGetValue(user, "formattedName").Replace(" ", "");
            Email = TryGetValue(user, "emailAddress");
            Industry = TryGetValue(user, "industry");
            Summary = TryGetValue(user, "summary");
            Headline = TryGetValue(user, "headline");
            Positions = TryGetValueAndSerialize(user, "positions");
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the LinkedIn user obtained from the endpoint https://api.linkedin.com/v1/people/~
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the LinkedIn access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the LinkedIn access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the LinkedIn user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the LinkedIn username
        /// </summary>
        [Obsolete("LinkedIn doesn't return a username claim. Use Name instead.")]
        public string UserName { get; private set; }

        /// <summary>
        /// Get the user's first name
        /// </summary>
        public string GivenName { get; private set; }

        /// <summary>
        /// Get the user's last name
        /// </summary>
        public string FamilyName { get; private set; }

        /// <summary>
        /// Describes the users membership profile
        /// </summary>
        public string Summary { get; private set; }

        /// <summary>
        /// Industry the member belongs to
        /// https://developer.linkedin.com/docs/reference/industry-codes
        /// </summary>
        public string Industry { get; set; }

        /// <summary>
        /// The members headline
        /// </summary>
        public string Headline { get; set; }

        /// <summary>
        /// Member's current positions
        /// https://developer.linkedin.com/docs/fields/positions
        /// </summary>
        public string Positions { get; set; }

        public string Link { get; private set; }

        /// <summary>
        /// Gets the LinkedIn email
        /// </summary>
        public string Email { get; private set; }

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

        private static string TryGetValueAndSerialize(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? JsonConvert.SerializeObject(value) : null;
        }
    }
}
