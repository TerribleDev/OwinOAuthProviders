// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.MyHeritage.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class MyHeritageAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="MyHeritageAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The MyHeritage user information</param>
        /// <param name="accessToken">MyHeritage Access token</param>
        /// <param name="refreshToken">MyHeritage Refresh token</param>
        public MyHeritageAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string refreshToken)
            : base(context)
        {
            AccessToken = accessToken;
            RefreshToken = refreshToken;
            User = user;
            Name = user.SelectToken("name").ToString();
            Id = user.SelectToken("translator_id").ToString();
        }

        /// <summary>
        /// Gets the user json object that was retrieved from MyHeritage
        /// during the authorization process.
        /// </summary>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the user name extracted from the MyHeritage API during
        /// the authorization process.
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the user id extracted from the MyHeritageAPI during the
        /// authorization process.
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the MyHeritage access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the MyHeritage refresh token
        /// </summary>
        public string RefreshToken { get; private set; }

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
