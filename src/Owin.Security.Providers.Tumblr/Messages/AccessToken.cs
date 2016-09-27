// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

namespace Owin.Security.Providers.Tumblr.Messages
{
    /// <summary>
    /// Tumblr access token
    /// </summary>
    public class AccessToken : RequestToken
    {
        /// <summary>
        /// Gets or sets the Tumblr User ID
        /// </summary>
        public string UserId { get; set; } 

        public dynamic User { get; set; }
    }
}
