// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Bitbucket
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class BitbucketAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="BitbucketAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Bitbucket Access token</param>
        public BitbucketAuthenticatedContext(IOwinContext context, JObject user, string accessToken)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;

            Id = TryGetValue(user, "uuid");
            Name = TryGetValue(user, "display_name");
            Link = TryGetValue(user, "website");
            UserName = TryGetValue(user, "username");
            Email = TryGetValue(user, "email");
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Bitbucket user obtained from the User Info endpoint. By default this is https://api.bitbucket.org/2.0/user but it can be
        /// overridden in the options
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Bitbucket access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Bitbucket user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        public string Link { get; private set; }

        /// <summary>
        /// Gets the Bitbucket username
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the Bitbucket email
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
