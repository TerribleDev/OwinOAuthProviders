using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Yammer.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class YammerAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="YammerAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Yammer Access token</param>
        public YammerAuthenticatedContext(IOwinContext context, dynamic user, string accessToken) : base(context)
        {
            User = user;
            AccessToken = accessToken;
            Id = user.id;
            Name = user.full_name;
            Url = user.url;
            Network = user.network_name;
            if (user.contact.email_addresses != null)
            {
                foreach (var eml in user.contact.email_addresses)
                {
                    if (eml.type == "primary") PrimaryEmail = eml.address;
                }
            }
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Yammer user
        /// </remarks>
        public dynamic User { get; private set; }

        /// <summary>
        /// Gets the Yammer access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Yammer user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the Yammer full_name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the Yammer url
        /// </summary>
        public string Url { get; private set; }

        /// <summary>
        /// Gets the Yammer Primary Email
        /// </summary>
        public string PrimaryEmail { get; private set; }

        /// <summary>
        /// Gets the yammer network_name
        /// </summary>
        public string Network { get; private set; }

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
