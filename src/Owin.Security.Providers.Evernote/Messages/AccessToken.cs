// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

namespace Owin.Security.Providers.Evernote.Messages
{
    /// <summary>
    /// Evernote access token
    /// </summary>
    public class AccessToken : RequestToken
    {
        /// <summary>
        /// Gets or sets the Evernote User ID
        /// </summary>
        public string UserId { get; set; }

        /// <summary>
        /// Gets or sets the Evernote User Name
        /// </summary>
        public string UserName { get; set; }

        public string Shard { get; set; }

        public string NoteStoreUrl { get; set; }

        public string WebApiUrlPrefix { get; set; }
    }
}
