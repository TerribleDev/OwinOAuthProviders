// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Yahoo
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class YahooAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="YahooAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON serialized user</param>
        /// <param name="userId">Yahoo user ID</param>
        /// <param name="accessToken">Yahoo access token</param>
        /// <param name="accessTokenSecret">Yahoo access token secret</param>
        public YahooAuthenticatedContext(
            IOwinContext context,
            JObject user,
            string userId,
            string accessToken,
            string accessTokenSecret)
            : base(context)
        {
            User = user;
            UserId = userId;
            NickName = TryGetValue(user, "nickname");
            AccessToken = accessToken;
            AccessTokenSecret = accessTokenSecret;
            Email = GetEmail(user);
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Yahoo user obtained from Yahoo
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the primary email address for the account
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the Yahoo user ID
        /// </summary>
        public string UserId { get; private set; }

        /// <summary>
        /// Gets the Yaho0 nickname
        /// </summary>
        public string NickName { get; private set; }

        /// <summary>
        /// Gets the Yahoo access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Yahoo access token secret
        /// </summary>
        public string AccessTokenSecret { get; private set; }

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

        private string GetEmail(JObject user)
        {
            if (user != null)
            {
                try
                {
                    JToken email = null;
                    JToken emails = null;

                    // Get the emails element
                    user.TryGetValue("emails", out emails);

                    if (emails != null)
                    {
                        if (emails.Type == JTokenType.Array)
                        {
                            // Try and get the primary email address
                            email = emails.FirstOrDefault(e => e["primary"]!=null && e["primary"].ToString() == "true");

                            // If no primary email was located, select the first email we can find
                            if (email == null)
                                email = emails.FirstOrDefault();
                        }
                        else if (emails.Type == JTokenType.Object)
                        {
                            // If the emails element is a single object and not an array, then take that object as the email object
                            email = emails;
                        }

                        // If we managed to find an email (primary or otherwise), then return the email
                        if (email != null && email["handle"] != null)
                            return email["handle"].ToString();
                    }
                }
                catch
                {
                    // Suppress any exception here
                }
            }

            return null;
        }
    }
}
