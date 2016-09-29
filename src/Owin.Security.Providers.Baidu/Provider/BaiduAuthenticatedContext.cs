// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Baidu
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class BaiduAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="BaiduAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Baidu Access token</param>
        public BaiduAuthenticatedContext(IOwinContext context, JObject user, string accessToken)
            : base(context)
        {
            AccessToken = accessToken;
            User = user;

            Userid = TryGetValue(user, "userid");
            UserName = TryGetValue(user, "username");
            RealName = TryGetValue(user, "realname");
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Baidu user obtained from the endpoint https://api.dropbox.com/1/account/info
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Baidu OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Baidu user ID
        /// </summary>
        public string Userid { get; private set; }

        /// <summary>
        /// The name of the user
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// The real name of the user
        /// </summary>
        public string RealName { get; private set; }

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
