// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

namespace Owin.Security.Providers.Yahoo.Messages
{
    /// <summary>
    /// Yahoo access token
    /// </summary>
    public class AccessToken : RequestToken
    {
        /// <summary>
        /// Gets or sets the Yahoo User ID
        /// </summary>
        public string UserId { get; set; }
    }
}
