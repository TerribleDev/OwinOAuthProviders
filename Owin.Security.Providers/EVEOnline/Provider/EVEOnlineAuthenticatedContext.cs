// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.EveOnline
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class EveOnlineAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="EveOnlineAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="characterData">The JSON-serialized userId</param>
        /// 
        /// <param name="accessToken">EveOnline Access token</param>
        /// <param name="expires">Seconds until expiration</param>
        public EveOnlineAuthenticatedContext(IOwinContext context, JObject characterData, string accessToken, string refreshToken, string expires)
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
        /// Contains the EveOnline user ID 
        /// </remarks>
        public JObject JsonCharacterId { get; private set; }

        /// <summary>
        /// Gets EveOnline OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets EveOnline OAuth refresh token
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets EveOnline access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets EveOnline character owner hash. It changes only if character is transfered
        /// to other account.
        /// </summary>
        public string CharacterOwnerHash { get; private set; }

        /// <summary>
        /// Gets EveOnline character ID
        /// </summary>
        public string CharacterId { get; private set; }

        /// <summary>
        /// Gets the EveOnline character name
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