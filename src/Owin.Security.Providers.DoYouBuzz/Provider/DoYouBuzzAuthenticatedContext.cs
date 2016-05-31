using System.Security.Claims;
using Microsoft.Owin.Security.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.DoYouBuzz
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class DoYouBuzzAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="DoYouBuzzAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="userId">DoYouBuzz user ID</param>
        /// <param name="accessToken">DoYouBuzz access token</param>
        /// <param name="accessTokenSecret">DoYouBuzz access token secret</param>
        public DoYouBuzzAuthenticatedContext(IOwinContext context, string userId, string accessToken, string accessTokenSecret)
            : base(context)
        {
            UserId = userId;
            AccessToken = accessToken;
            AccessTokenSecret = accessTokenSecret;
        }

        /// <summary>
        /// Gets the DoYouBuzz user ID
        /// </summary>
        public string UserId { get; private set; }

        /// <summary>
        /// Gets the DoYouBuzz access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the DoYouBuzz access token secret
        /// </summary>
        public string AccessTokenSecret { get; private set; }

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