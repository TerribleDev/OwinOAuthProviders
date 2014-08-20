// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using Microsoft.Owin.Security;

namespace Owin.Security.Providers.TripIt.Messages
{
    /// <summary>
    /// TripIt request token
    /// </summary>
    public class RequestToken
    {
        /// <summary>
        /// Gets or sets the TripIt token
        /// </summary>
        public string Token { get; set; }

        /// <summary>
        /// Gets or sets the TripIt token secret
        /// </summary>
        public string TokenSecret { get; set; }

        public bool CallbackConfirmed { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }
    }
}
