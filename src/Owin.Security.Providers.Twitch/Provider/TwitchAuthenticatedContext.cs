// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Twitch
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class TwitchAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="TwitchAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="users">The JSON-serialized users</param>
        /// <param name="accessToken">Twitch Access token</param>
        public TwitchAuthenticatedContext(IOwinContext context, JObject users, string accessToken)
            : base(context)
        {
            User = (JObject) ((JArray) users.GetValue("data")).First;
            AccessToken = accessToken;

            Id = TryGetValue(User, "_id");
            Name = TryGetValue(User, "name");
            Link = TryGetValue(User, "url");
            UserName = TryGetValue(User, "name");
            Email = TryGetValue(User, "email");
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Twitch user obtained from the User Info endpoint. By default this is https://api.twitch.tv/helix/users but it can be
        /// overridden in the options
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Twitch access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Twitch user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        public string Link { get; private set; }

        /// <summary>
        /// Gets the Twitch username
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the Twitch email
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
    }
}
