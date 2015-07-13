namespace Owin.Security.Providers.Imgur.Provider
{
    using System.Security.Claims;

    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    /// <summary>Contains information about the login session and the user's <see cref="System.Security.Claims.ClaimsIdentity"/>.</summary>
    public class ImgurAuthenticatedContext : BaseContext<ImgurAuthenticationOptions>
    {
        /// <summary>Creates a new <see cref="ImgurAuthenticatedContext"/>.</summary>
        /// <param name="context">The OWIN context of the autentication request.</param>
        /// <param name="options">The <see cref="ImgurAuthenticationOptions"/> used to set up the <see cref="ImgurAuthenticationMiddleware"/>.</param>
        public ImgurAuthenticatedContext(IOwinContext context, ImgurAuthenticationOptions options)
            : base(context, options)
        {
        }

        /// <summary>Gets or sets the access token for the authenticated user.</summary>
        public string AccessToken { get; set; }

        /// <summary>Gets or sets the account id of the authenticated user.</summary>
        public int AccountId { get; set; }

        /// <summary>Gets or sets the account username of the authenticated user.</summary>
        public string AccountUsername { get; set; }

        /// <summary>Gets or sets the duration of the access token.</summary>
        public int ExpiresIn { get; set; }

        /// <summary>Gets or sets the <see cref="ClaimsIdentity"/> for the authenticated user.</summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>Gets or sets the <see cref="AuthenticationProperties"/> of the authentication request.</summary>
        public AuthenticationProperties Properties { get; set; }

        /// <summary>Gets or sets the refresh token for the authenticated user.</summary>
        public string RefreshToken { get; set; }

        /// <summary>Gets or sets the scope of the access token.</summary>
        public string Scope { get; set; }

        /// <summary>Gets or sets the type of the access token.</summary>
        public string TokenType { get; set; }
    }
}
