// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.Typeform
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class TypeformAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="TypeformAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="userJson">The JSON-serialized user</param>
        /// <param name="accessToken">Typeform Access token</param>
        /// <param name="refreshToken">Typeform Refresh token</param>
        /// <param name="instanceUrl">Typeform instance url</param>
        public TypeformAuthenticatedContext(IOwinContext context, string accessToken)
            : base(context)
        {
            AccessToken = accessToken;

            // Typeform doesn't supply a unique identifier for the user,
            // however according to https://developer.typeform.com/get-started/applications/
            // the access token doesn't expire so we can use it as a proxy for UserId
            UserId = ComputeHash(accessToken);
        }

        /// <summary>
        /// Gets the Typeform access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Typeform User ID
        /// </summary>
        public string UserId { get; private set; }


        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        /// <summary>
        /// 
        /// </summary>
        private static string ComputeHash(string input) 
        {
            if (String.IsNullOrEmpty(input)) return null;

            byte[] bytes;
            using (var hash = System.Security.Cryptography.SHA1.Create()) {
                bytes = hash.ComputeHash(System.Text.Encoding.UTF8.GetBytes(input));
            }

            return String.Concat(bytes.Select(x => x.ToString("x2")));
        }
    }
}
