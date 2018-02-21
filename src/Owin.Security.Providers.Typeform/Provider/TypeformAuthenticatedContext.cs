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
            // so we generate a fake one because OWIN pipeline requires it
            // This means you can only use Typeform OAuth for authorization, not authentication because
            // each time you sign in with the same Typeform account this provider will yield a distinct UserId
            UserId = Guid.NewGuid().ToString();
        }

        /// <summary>
        /// Gets the Typeform access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Typeform User ID
        /// </summary>
        [Obsolete("This is not the real UserId because Typeform OAuth endpoint does not provide it. Use Typeform OAuth for authorization, not authentication.")]
        public string UserId { get; private set; }


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
