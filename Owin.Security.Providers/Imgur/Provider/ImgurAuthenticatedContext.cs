namespace Owin.Security.Providers.Imgur.Provider
{
    using System.Security.Claims;

    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    /// <summary></summary>
    public class ImgurAuthenticatedContext : BaseContext<ImgurAuthenticationOptions>
    {
        /// <summary></summary>
        /// <param name="context"></param>
        /// <param name="options"></param>
        public ImgurAuthenticatedContext(IOwinContext context, ImgurAuthenticationOptions options)
            : base(context, options)
        {
        }

        /// <summary></summary>
        public string AccessToken { get; set; }

        /// <summary></summary>
        public int AccountId { get; set; }

        /// <summary></summary>
        public string AccountUsername { get; set; }

        /// <summary></summary>
        public int ExpiresIn { get; set; }

        /// <summary></summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary></summary>
        public AuthenticationProperties Properties { get; set; }

        /// <summary></summary>
        public string RefreshToken { get; set; }

        /// <summary></summary>
        public string Scope { get; set; }

        /// <summary></summary>
        public string TokenType { get; set; }
    }
}
