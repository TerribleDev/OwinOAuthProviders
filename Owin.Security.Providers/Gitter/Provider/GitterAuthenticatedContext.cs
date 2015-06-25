// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Gitter.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class GitterAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="GitterAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Gitter Access token</param>
        /// <param name="token_type">Indicates access level of application</param>
        public GitterAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string token_type)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
            TokenType = token_type;

            UserId = TryGetValue(user, "id");
            Username = TryGetValue(user, "username");
            UserDisplayName = TryGetValue(user, "displayName");
            UserUrl = TryGetValue(user, "url");
            UserAvatarUrlSmall = TryGetValue(user, "avatarUrlSmall");
            UserAvatarUrlMedium = TryGetValue(user, "avatarUrlMedium");
            UserGV = TryGetValue(user, "gv");
        }

        /// <summary>
        /// The user GV
        /// </summary>
        public string UserGV { get; set; }

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
