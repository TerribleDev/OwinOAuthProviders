using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System;
using System.Globalization;

namespace Owin.Security.Providers.ConstantContact.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class ConstantContactAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="ConstantContactAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The Constant Contact response information</param>
        /// <param name="accessToken">ConstantContact Access token</param>
        /// <param name="refreshToken">ConstantContact Refresh token</param>
        public ConstantContactAuthenticatedContext(IOwinContext context, string accessToken, string username, string expires)
            : base(context)
        {
            AccessToken = accessToken;
            UserName = username;
            int expiresValue;
            if (int.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }
        }


        /// <summary>
        /// Gets the ConstantContact access token
        /// </summary>
        public string AccessToken { get; private set; }
        /// <summary>
        /// Gets the username passed back by ConstantContact
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the Contant Contact access token expiration time in seconds
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

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
