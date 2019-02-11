// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Google.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class GoogleAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="GoogleAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="userInfo">The JSON-serialized user_info. Format described here: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims</param>
        /// <param name="accessToken">Google Access token</param>
        /// <param name="expires">Seconds until expiration</param>
        /// <param name="refreshToken"></param>
        public GoogleAuthenticatedContext(IOwinContext context, JObject userInfo, string accessToken, string expires, string refreshToken)
            : base(context)
        {
            UserInfo = userInfo;
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            int expiresValue;
            if (int.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            // See https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims for a list of properties
            Id = TryGetValue(userInfo, "sub");
            Name = TryGetValue(userInfo, "name");
            Link = TryGetValue(userInfo, "profile");
            UserName = TryGetValue(userInfo, "name").Replace(" ", "");

            var email = TryGetValue(userInfo, "email");
            if (email != null)
                Email = email;
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Google user obtained from the endpoint https://www.googleapis.com/oauth2/v3/userinfo
        /// </remarks>
        public JObject UserInfo { get; private set; }

        /// <summary>
        /// Gets the Google OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Google OAuth refresh token.  This is only available when the RequestOfflineAccess property of <see cref="GoogleAuthenticationOptions"/> is set to true
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets the Google access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the Google user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        public string Link { get; private set; }

        /// <summary>
        /// Gets the Google username
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the Google email address for the account
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
