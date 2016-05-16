// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Discord.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class DiscordAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="DiscordAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Discord Access token</param>
        /// <param name="expires">Seconds until expiration</param>
        /// <param name="refreshToken"></param>
        public DiscordAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string expires, string refreshToken)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
            RefreshToken = refreshToken;
            int expiresValue;
            if (int.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }
            Id = TryGetValue(user, "id");
            UserName = TryGetValue(user, "username");
            Discriminator = TryGetValue(user, "discriminator");
            Avatar = TryGetValue(user, "avatar");
            Email = TryGetValue(user, "email");
            Verified = TryGetValue(user, "verified") == "true";
        }

        public string RefreshToken { get; set; }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Discord user
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Discord access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Discord access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the Discord user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the Discord user discriminator
        /// </summary>
        public string Discriminator { get; private set; }

        /// <summary>
        /// Gets the Discord user avatar
        /// </summary>
        public string Avatar { get; private set; }

        /// <summary>
        /// Gets the Discord user email
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the Discord username
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets whether the user is verified or not.
        /// </summary>
        public bool Verified { get; private set; } = false;

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
