// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System;

namespace Owin.Security.Providers.VKontakte.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class VKontakteAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="VKontakteAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">VK Access token</param>
        /// <param name="apiVersion">VK API version</param>
        public VKontakteAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string apiVersion)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
            ApiVersion = apiVersion;

            if (CompareVersions(ApiVersion, "5.0") < 0)
            {
                Id = TryGetValue(user, "uid");
            }
            else
            {
                Id = TryGetValue(user, "id");
            }

            var firstName = TryGetValue(user, "first_name");
            var lastName = TryGetValue(user, "last_name");
            UserName = firstName + " " + lastName;
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the VK user obtained from the User Info endpoint. By default this is https://api.vk.com/method/users.get but it can be
        /// overridden in the options
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the VK access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the VK user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        public string ApiVersion { get; private set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }

        public static int CompareVersions(string current, string compared)
        {
            Version vA = new Version(current.Replace(",", "."));
            Version vB = new Version(compared.Replace(",", "."));

            return vA.CompareTo(vB);
        }
    }
}
