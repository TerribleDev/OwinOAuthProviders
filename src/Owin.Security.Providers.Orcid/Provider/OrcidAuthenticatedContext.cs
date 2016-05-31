// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using Owin.Security.Providers.Orcid.Message;

namespace Owin.Security.Providers.Orcid
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class OrcidAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="VKontakteAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">VK Access token</param>
        public OrcidAuthenticatedContext(IOwinContext context, JObject user, string accessToken)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the user obtained from the User Info endpoint. By default this ishttp://pub.orcid.org/v1.2/{orcid}/orcid-profile/ but it can be
        /// overridden in the options
        /// </remarks>
        public JObject User { get; internal set; }

        /// <summary>
        /// Gets the VK access token
        /// </summary>
        public string AccessToken { get; internal set; }

        /// <summary>
        /// Gets the user ID
        /// </summary>
        public string Id { get; internal set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string UserName { get; internal set; }

        /// <summary>
        /// Gets the user's last name
        /// </summary>
        public string LastName { get; internal set; }
        /// <summary>
        /// Gets the user's first name
        /// </summary>
        public string FirstName { get; internal set; }

        /// <summary>
        /// Gets the user's Email
        /// </summary>
        public string Email { get; internal set; }

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
