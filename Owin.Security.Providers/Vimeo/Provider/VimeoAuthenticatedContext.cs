// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System.Security.Claims;

namespace Owin.Security.Providers.Vimeo
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class VimeoAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="VimeoAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Vimeo Access token</param>
        public VimeoAuthenticatedContext(IOwinContext context, JObject user, string accessToken)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
            
            Name = TryGetValue(user, "name");

            var uri = TryGetValue(user, "uri");
            if (!string.IsNullOrEmpty(uri))
            {
                Id = uri.Substring(uri.LastIndexOf("/") + 1); // parse format /users/123456
            }
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Vimeo user included in the Authentication response
        /// https://developer.vimeo.com/api/endpoints/me
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Vimeo OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Vimeo user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Get the name of the user
        /// </summary>
        public string Name { get; private set; }

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