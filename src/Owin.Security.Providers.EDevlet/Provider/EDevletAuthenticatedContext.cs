// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.EDevlet.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class EDevletAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="EDevletAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="userInfo">The JSON-serialized user_info. Format described here: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims</param>
        /// <param name="accessToken">EDevlet Access token</param>
        /// <param name="expires">Seconds until expiration</param>
        /// <param name="refreshToken"></param>
        public EDevletAuthenticatedContext(IOwinContext context, string identityNo, string name, string surname, string accessToken)
            : base(context)
        {

            AccessToken = accessToken;



            IdentityNo = identityNo;
            Name = name;
            Surname = surname;

        }


        /// <summary>
        /// Gets the EDevlet OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }



        /// <summary>
        /// Gets the users national identity number
        /// </summary>
        public string IdentityNo { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the user's surname
        /// </summary>
        public string Surname { get; private set; }

        /// <summary>
        /// Gets the user's full name
        /// </summary>
        public string FullName => $"{Name} {Surname}";


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
