// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Collections.Specialized;
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
            CosignResposponse = cosignResponse;
            string[] returnedData = CosignResposponse.Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);
            Id = TryGetValue(returnedData, "id");
            UserId = TryGetValue(returnedData, "userid");
            IpAddress = TryGetValue(returnedData, "ipaddress");
            Realm = TryGetValue(returnedData, "realm");
        }

        /// <summary>
        /// Gets the Cosign response
        /// </summary>
        public string CosignResposponse { get; private set; }

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
                    if (cosignData.GetUpperBound(0)>=0)
                    return cosignData[1];
                    return "";
                case "userid":
                    if (cosignData.GetUpperBound(0) >= 1)
                        return cosignData[2];
                    return "";
                case "id":
                    if (cosignData.GetUpperBound(0) >= 1)
                        return sha256_hash( cosignData[2]);
                    return "";
                case "realm":
                    if (cosignData.GetUpperBound(0) >=2)
                        return cosignData[3].Trim(new char[]{ Environment.NewLine.ToCharArray()[0]} );
                    return "";
                default:
                    return "";
            }

        }


        private static string sha256_hash(string value)
        {
            StringBuilder Sb = new StringBuilder();

            using (SHA256 hash = SHA256.Create())
            {
                Encoding enc = Encoding.UTF8;
                byte[] result = hash.ComputeHash(enc.GetBytes(value));

                foreach (byte b in result)
                    Sb.Append(b.ToString("x2"));
            }

            return Sb.ToString();
        }
    }
}
