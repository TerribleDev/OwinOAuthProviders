using Microsoft.Owin.Security;

namespace Owin.Security.Providers.Gitter
{
    public class GitterAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        ///     Initializes a new <see cref="GitterAuthenticationOptions" />
        /// </summary>
        public GitterAuthenticationOptions()
            : base("Gitter")
        {
            AuthenticationMode = AuthenticationMode.Passive;
        }

        /// <summary>
        ///     Gets or sets the Google supplied Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the Google supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

    }
}