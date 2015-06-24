// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Gitter.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class GitterAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="GitterAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Slack Access token</param>
        /// <param name="scope">Indicates access level of application</param>
        public GitterAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string scope)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
            Scope = scope.Split(',');
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Gitter user
        /// </remarks>
        public JObject User { get; set; }

        /// <summary>
        /// Gets the Gitter access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the scope of the application's access to user info
        /// </summary>
        public IList<string> Scope { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }
    }
}
