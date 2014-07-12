// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.StackExchange
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class StackExchangeAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="StackExchangeAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">StackExchange Access token</param>
        /// <param name="expires">Seconds until expiration</param>
        public StackExchangeAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string expires)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            Id = TryGetValue(user, "user_id");
            Name = TryGetValue(user, "display_name");
            Link = TryGetValue(user, "link");
            UserName = TryGetValue(user, "display_name").Replace(" ", "");
            ProfileImage = TryGetValue(user, "profile_image"); 
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// The endpoint https://api.stackexchange.com/2.2/me?order=desc&sort=reputation&site=stackoverflow&key={{key}}&access_token={{access_token}} returns a list of user accounts. This represents the first user account in that list.
        /// The user object schema can be found here - http://api.stackexchange.com/docs/types/user
        /// Sample user objects can be viewed in the response of /users API here - http://api.stackexchange.com/docs/users#order=desc&sort=reputation&filter=default&site=stackoverflow&run=true
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the StackExchange access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the StackExchange access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the StackExchange user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the link to the StackExchange profile
        /// </summary>
        public string Link { get; private set; }

        /// <summary>
        /// Gets the StackExchange username
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the StackExchange profile image URL
        /// </summary>
        public string ProfileImage { get; private set; }

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
            return user != null && user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}
