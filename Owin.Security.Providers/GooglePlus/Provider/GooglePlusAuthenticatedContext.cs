// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.GooglePlus.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class GooglePlusAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="GooglePlusAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="person"></param>
        /// <param name="accessToken">Google+ Access token</param>
        /// <param name="expires">Seconds until expiration</param>
        public GooglePlusAuthenticatedContext(IOwinContext context, JObject user, JObject person, string accessToken, string expires, string refreshToken)
            : base(context)
        {
            User = user;
            Person = person;
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            Id = TryGetValue(person, "id");
            Name = TryGetValue(person, "displayName");
            Link = TryGetValue(person, "url");
            UserName = TryGetValue(person, "displayName").Replace(" ", "");

            var email = (from e in person["emails"]
                where e["type"].ToString() == "account"
                select e).FirstOrDefault();
            if (email != null)
                Email = email["value"].ToString();
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Google user obtained from the endpoint https://www.googleapis.com/oauth2/v3/userinfo
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the JSON-serialized person
        /// </summary>
        /// <remarks>
        /// Contains the Google+ person obtained from the endpoint https://www.googleapis.com/plus/v1/people/me.  For more information
        /// see https://developers.google.com/+/api/latest/people
        /// </remarks>
        public JObject Person { get; private set; }

        /// <summary>
        /// Gets the Google OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Google OAuth refresh token.  This is only available when the RequestOfflineAccess property of <see cref="GooglePlusAuthenticationOptions"/> is set to true
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets the Google+ access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the Google+ user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        public string Link { get; private set; }

        /// <summary>
        /// Gets the Google+ username
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the Google+ email address for the account
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
