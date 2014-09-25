// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Security.Claims;
using System.Linq;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using Owin.Security.Providers.ArcGISOnline.Provider;

namespace Owin.Security.Providers.ArcGISOnline
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class ArcGISOnlineAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="ArcGISOnlineAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The ArcGIS Online user</param>
        /// <param name="accessToken">ArcGISOnline Access token</param>
        public ArcGISOnlineAuthenticatedContext(IOwinContext context, ArcGISOnlineUser user, string accessToken)
            : base(context)
        {
            AccessToken = accessToken;

            Id = user.user.username;
            Name = user.user.fullName;
            Link = "https://www.arcgis.com/sharing/rest/community/users/" + Id;
            UserName = Id;
            Email = user.user.email;
        }

        /// <summary>
        /// Gets the ArcGISOnline access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the ArcGISOnline user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the user's email
        /// </summary>
        public string Email { get; private set; }

        public string Link { get; private set; }

        /// <summary>
        /// Gets the ArcGISOnline username
        /// </summary>
        public string UserName { get; private set; }

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
