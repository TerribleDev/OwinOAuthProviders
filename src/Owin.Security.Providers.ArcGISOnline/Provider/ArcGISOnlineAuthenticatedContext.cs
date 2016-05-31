// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
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
        /// <param name="accessToken">ArcGIS Online Access token</param>
        /// <param name="refreshToken">ArcGIS Online Refresh token</param>
        public ArcGISOnlineAuthenticatedContext(IOwinContext context, ArcGISOnlineUser user, string accessToken, string refreshToken)
            : base(context)
        {
            AccessToken = accessToken;
            RefreshToken = refreshToken;
            Id = user.Username;
            Name = user.FullName;
            Link = "https://www.arcgis.com/sharing/rest/community/users/" + Id;
            UserName = Id;
            Email = user.Email;
        }

        /// <summary>
        /// Gets the ArcGIS Online access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the ArcGIS Online refresh token
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets the ArcGIS Online user ID
        /// </summary>
        public string Id { get; }

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
        /// Gets the ArcGIS Online username
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
