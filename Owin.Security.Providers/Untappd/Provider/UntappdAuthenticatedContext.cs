// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Untappd
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class UntappdAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="UntappdAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Untappd Access token</param>
        public UntappdAuthenticatedContext(IOwinContext context, JObject user, string accessToken)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;

            Id = user["response"]["user"]["id"].ToString();
            Name = user["response"]["user"]["first_name"].ToString() + " " + user["response"]["user"]["last_name"].ToString();
            Link = user["response"]["user"]["url"].ToString();
            UserName = user["response"]["user"]["user_name"].ToString();
            Email = user["response"]["user"]["settings"]["email_address"].ToString();
            AvatarUrl = user["response"]["user"]["user_avatar"].ToString();
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Untappd user obtained from the User Info endpoint. By default this is https://api.Untappd.com/user but it can be
        /// overridden in the options
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Untappd access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Untappd user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        public string Link { get; private set; }

        /// <summary>
        /// Gets the Untappd username
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the Untappd email
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the Untappd avatar url 100x100
        /// </summary>
        public string AvatarUrl { get; private set; }

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