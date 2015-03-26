// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Salesforce
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class SalesforceAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="SalesforceAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Salesforce Access token</param>
        /// <param name="refreshToken">Salesforce Refresh token</param>
        /// <param name="instanceUrl">Salesforce instance url</param>
        public SalesforceAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string refreshToken, string instanceUrl)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
            RefreshToken = refreshToken;
            InstanceUrl = instanceUrl;

            Id = TryGetValue(user, "id");
            UserId = TryGetValue(user, "user_id");
            OrganizationId = TryGetValue(user, "organization_id");
            UserName = TryGetValue(user, "username");
            NickName = TryGetValue(user, "nick_name");
            DisplayName = TryGetValue(user, "display_name");
            Email = TryGetValue(user, "email");
            FirstName = TryGetValue(user, "first_name");
            LastName = TryGetValue(user, "last_name");
            TimeZone = TryGetValue(user, "timezone");
            Active = TryGetValue(user, "active");
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Salesforce user obtained from the User Info endpoint. By default this is https://api.Salesforce.com/user but it can be
        /// overridden in the options
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Salesforce access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Salesforce refresh token, if the application's scope allows it
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets the Salesforce instance url
        /// </summary>
        public string InstanceUrl { get; private set; }

        /// <summary>
        /// Gets the Salesforce ID / User Info Endpoint
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the Salesforce User ID
        /// </summary>
        public string UserId { get; private set; }

        /// <summary>
        /// Gets the Salesforce Organization ID
        /// </summary>
        public string OrganizationId { get; private set; }

        /// <summary>
        /// Gets the Salesforce User Name
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the Salesforce Nick Name
        /// </summary>
        public string NickName { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string DisplayName { get; private set; }

        /// <summary>
        /// Gets the Salesforce User Email
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the user's First Name
        /// </summary>
        public string FirstName { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string LastName { get; private set; }

        /// <summary>
        /// Gets the user's Last Name
        /// </summary>
        public string TimeZone { get; private set; }

        /// <summary>
        /// Gets the user's Status
        /// </summary>
        public string Active { get; private set; }

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
