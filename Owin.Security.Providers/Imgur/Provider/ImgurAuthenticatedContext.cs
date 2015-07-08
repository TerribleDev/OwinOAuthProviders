namespace Owin.Security.Providers.Imgur.Provider
{
    using System.Security.Claims;

    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    public class ImgurAuthenticatedContext : BaseContext<ImgurAuthenticationOptions>
    {
        public ImgurAuthenticatedContext(IOwinContext context, ImgurAuthenticationOptions options)
            : base(context, options)
        {
        }

        public string AccessToken { get; set; }

        public int AccountId { get; set; }

        public string AccountUsername { get; set; }

        public int ExpiresIn { get; set; }

        public ClaimsIdentity Identity { get; set; }

        public AuthenticationProperties Properties { get; set; }

        public string RefreshToken { get; set; }

        public string Scope { get; set; }

        public string TokenType { get; set; }
    }
}
