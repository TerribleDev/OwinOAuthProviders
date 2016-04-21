// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Jawbone
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class JawboneAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="JawboneAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Jawbone Access token</param>
        public JawboneAuthenticatedContext(IOwinContext context, JObject user, string accessToken)
            : base(context)
        {
            AccessToken = accessToken;
            // Pull out the {{data:... from JSON which starts with {{meta:...{data:...
            foreach(var u in user)
            {
                if (u.Key.Equals("data"))
                {
                    User = (JObject)u.Value;
                    break;
                }
            }

            Id = TryGetValue(User, "xid");
            FirstName = TryGetValue(User, "first");
            LastName = TryGetValue(User, "last");
            ImageUrl = TryGetValue(User, "image");

            string weight = TryGetValue(User, "weight");
            decimal dWeight = 0L;
            Decimal.TryParse(weight, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out dWeight);
            Weight = dWeight;
            string height = TryGetValue(User, "height");
            decimal dHeight = 0L;
            Decimal.TryParse(height, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out dHeight);
            Height = dHeight;
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Jawbone user obtained from the endpoint https://jawbone.com/nudge/api/v.1.1/users/@me
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Jawbone OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Jawbone user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// The first name of the user
        /// </summary>
        public string FirstName { get; private set; }

        /// <summary>
        /// The last name of the user
        /// </summary>
        public string LastName { get; private set; }

        /// <summary>
        /// Conveience attribute to provide name of the user
        /// </summary>
        public string Name
        {
            get
            {
                return FirstName + " " + LastName;
            }
        }

        /// <summary>
        /// The image url of the user
        /// </summary>
        public string ImageUrl { get; private set; }

        /// <summary>
        /// The weight of the user
        /// </summary>
        public decimal Weight { get; private set; }

        /// <summary>
        /// The height of the user
        /// </summary>
        public decimal Height { get; private set; }

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
    }
}
