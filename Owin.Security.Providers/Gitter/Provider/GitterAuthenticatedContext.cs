// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.Gitter.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class GitterAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="GitterAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        public GitterAuthenticatedContext(IOwinContext context)
            : base(context)
        {

        }
    }
}
