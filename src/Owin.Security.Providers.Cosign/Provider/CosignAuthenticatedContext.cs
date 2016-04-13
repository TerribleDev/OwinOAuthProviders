// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.Cosign.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class CosignAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="CosignAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="cosignResponse">Response from Cosign server</param>
        public CosignAuthenticatedContext(IOwinContext context,  string cosignResponse): base(context)
        {
            CosignResponse = cosignResponse;
            var returnedData = CosignResponse.Split(new[] { " " }, StringSplitOptions.RemoveEmptyEntries);
            Id = TryGetValue(returnedData, "id");
            UserId = TryGetValue(returnedData, "userid");
            IpAddress = TryGetValue(returnedData, "ipaddress");
            Realm = TryGetValue(returnedData, "realm");
        }

        /// <summary>
        /// Gets the Cosign response
        /// </summary>
        public string CosignResponse { get; }

        /// <summary>
        /// Gets the Cosign ID
        /// </summary>
        public string Id { get; private set; }

     
        /// <summary>
        /// Gets the Cosign userId
        /// </summary>
        public string UserId { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user identity
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets the <see cref="IpAddress"/> representing the user ipaddress
        /// </summary>
        public string IpAddress { get; set; }
        /// <summary>
        /// Gets the <see cref="Realm"/> representing the user realm
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(string[] cosignData, string propertyName)
        {

            switch (propertyName.ToLower())
            {
                case "ipaddress":
                    return cosignData.GetUpperBound(0)>=0 ? cosignData[1] : "";
                case "userid":
                    return cosignData.GetUpperBound(0) >= 1 ? cosignData[2] : "";
                case "id":
                    return cosignData.GetUpperBound(0) >= 1 ? sha256_hash( cosignData[2]) : "";
                case "realm":
                    return cosignData.GetUpperBound(0) >=2 ? cosignData[3].Trim(Environment.NewLine.ToCharArray()[0]) : "";
                default:
                    return "";
            }
        }

        private static string sha256_hash(string value)
        {
            var sb = new StringBuilder();

            using (var hash = SHA256.Create())
            {
                var enc = Encoding.UTF8;
                var result = hash.ComputeHash(enc.GetBytes(value));

                foreach (var b in result)
                    sb.Append(b.ToString("x2"));
            }

            return sb.ToString();
        }
    }
}
