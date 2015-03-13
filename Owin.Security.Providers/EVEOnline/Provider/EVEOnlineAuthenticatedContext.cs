// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.EVEOnline
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class EVEOnlineAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="EVEOnlineAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="characterData">The JSON-serialized userId</param>
        /// 
        /// <param name="accessToken">EVEOnline Access token</param>
        /// <param name="expires">Seconds until expiration</param>
        public EVEOnlineAuthenticatedContext(IOwinContext context, JObject characterData, string accessToken, string refreshToken, string expires)
            : base(context)
        {
            JsonCharacterId = characterData;
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            CharacterId = TryGetValue(characterData, "CharacterID");
            CharacterName = TryGetValue(characterData, "CharacterName");
            CharacterOwnerHash = TryGetValue(characterData, "CharacterOwnerHash");
        }

        /// <summary>
        /// Gets the JSON-serialized user ID
        /// </summary>
        /// <remarks>
        /// Contains the EVEOnline user ID 
        /// </remarks>
        public JObject JsonCharacterId { get; private set; }

        /// <summary>
        /// Gets EVEOnline OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets EVEOnline OAuth refresh token
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets EVEOnline access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets EVEOnline character owner hash. It changes only if character is transfered
        /// to other account.
        /// </summary>
        public string CharacterOwnerHash { get; private set; }

        /// <summary>
        /// Gets EVEOnline character ID
        /// </summary>
        public string CharacterId { get; private set; }

        /// <summary>
        /// Gets the EVEOnline character name
        /// </summary>
        public string CharacterName { get; private set; }

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