using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using Owin.Security.Providers.Flickr.Messages;

namespace Owin.Security.Providers.Flickr {
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class FlickrAuthenticatedContext : BaseContext {
         /// <summary>
        /// Initializes a <see cref="FlickrAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="accessToken">Flick access toke</param>
        public FlickrAuthenticatedContext(IOwinContext context, AccessToken accessToken)
            : base(context)
        {
            FullName = accessToken.FullName;
            UserId = accessToken.UserId;
            UserName = accessToken.UserName;
            AccessToken = accessToken.Token;
            AccessTokenSecret = accessToken.TokenSecret;
        }

        /// <summary>
        /// Gets user full name
        /// </summary>
        public string FullName { get; private set; }

        /// <summary>
        /// Gets the Flickr user ID
        /// </summary>
        public string UserId { get; private set; }

        /// <summary>
        /// Gets the Flickr username
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the Flickr access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Flickr access token secret
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
