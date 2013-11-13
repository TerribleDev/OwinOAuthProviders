// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Yahoo
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class YahooAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="YahooAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON serialized user</param>
        /// <param name="userId">Yahoo user ID</param>
        /// <param name="accessToken">Yahoo access token</param>
        /// <param name="accessTokenSecret">Yahoo access token secret</param>
        public YahooAuthenticatedContext(
            IOwinContext context,
            JObject user,
            string userId,
            string accessToken,
            string accessTokenSecret)
            : base(context)
        {
            User = user;
            UserId = userId;
            NickName = TryGetValue(user, "nickname");
            AccessToken = accessToken;
            AccessTokenSecret = accessTokenSecret;
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the LinkedIn user obtained from the endpoint http://social.yahooapis.com/v1/user/{guid}/profile/usercard
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Yahoo user ID
        /// </summary>
        public string UserId { get; private set; }

        /// <summary>
        /// Gets the Yaho0 nickname
        /// </summary>
        public string NickName { get; private set; }

        /// <summary>
        /// Gets the Yahoo access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Yahoo access token secret
        /// </summary>
        public string AccessTokenSecret { get; private set; }

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
