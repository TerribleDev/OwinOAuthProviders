using System;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using System.Collections.Generic;
using System.Security.Claims;
using System.Xml.Linq;

namespace Owin.Security.Providers.OpenID
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class OpenIDAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="OpenIDAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="identity">The <see cref="ClaimsIdentity"/> representing the user</param>
        /// <param name="properties">A property bag for common authentication properties</param>
        /// <param name="responseMessage"></param>
        /// <param name="attributeExchangeProperties"></param>
        public OpenIDAuthenticatedContext(
            IOwinContext context,
            ClaimsIdentity identity,
            AuthenticationProperties properties,
            XElement responseMessage,
            IDictionary<string, string> attributeExchangeProperties)
            : base(context)
        {
            Identity = identity;
            Properties = properties;
            ResponseMessage = responseMessage;
            AttributeExchangeProperties = attributeExchangeProperties;
            ProtocolExtensionData = new Dictionary<Type, object>();
        }

        /// <summary>
        /// Gets or sets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        public XElement ResponseMessage { get; set; }

        public IDictionary<string, string> AttributeExchangeProperties { get; private set; }

        public IDictionary<Type, object> ProtocolExtensionData { get; private set; }
    }
}
