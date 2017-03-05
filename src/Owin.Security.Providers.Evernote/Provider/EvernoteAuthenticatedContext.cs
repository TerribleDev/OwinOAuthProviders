// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Owin.Security.Providers.Evernote.Messages;

namespace Owin.Security.Providers.Evernote
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class EvernoteAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="EvernoteAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="accessToken">Evernote access toke</param>
        public EvernoteAuthenticatedContext(IOwinContext context, AccessToken accessToken)
            : base(context)
        {
            UserId = accessToken.UserId;
            UserName = accessToken.UserName;
            AccessToken = accessToken.Token;
            NoteStoreUrl = accessToken.NoteStoreUrl;
        }

        /// <summary>
        /// Gets the Evernote user ID
        /// </summary>
        public string UserId { get; private set; }

        /// <summary>
        /// Gets the Evernote username
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// Gets the Evernote access token
        /// </summary>
        public string AccessToken { get; private set; }

        public string NoteStoreUrl { get; set; }

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
