using Microsoft.Owin.Security;

namespace Owin.Security.Providers.Xing.Messages
{
    /// <summary>
    /// Xing request token
    /// </summary>
    public class RequestToken
    {
        /// <summary>
        /// Gets or sets the Xing token
        /// </summary>
        public string Token { get; set; }

        /// <summary>
        /// Gets or sets the Xing token secret
        /// </summary>
        public string TokenSecret { get; set; }

        /// <summary>
        /// Indicates that callback is confirmed or not
        /// </summary>
        public bool CallbackConfirmed { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }
    }
}