using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Owin.Security.Providers.Tumblr.Messages;

namespace Owin.Security.Providers.Tumblr.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class TumblrAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="TumblrAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="accessToken">Flick access toke</param>
        public TumblrAuthenticatedContext(IOwinContext context, AccessToken accessToken)
            : base(context)
        {
            UserId = accessToken.UserId;
            AccessToken = accessToken.Token;
            AccessTokenSecret = accessToken.TokenSecret;
            User = accessToken.User;
        }

        /// <summary>
        /// Gets the Tumblr user ID
        /// </summary>
        public string UserId { get; private set; }

        /// <summary>
        /// Gets the Tumblr access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Tumblr access token secret
        /// </summary>
        public string AccessTokenSecret { get; private set; }

        /// <summary>
        /// Gets the Tumblr user info
        /// </summary>
        public dynamic User { get; private set; }

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
