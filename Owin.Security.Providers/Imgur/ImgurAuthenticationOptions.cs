namespace Owin.Security.Providers.Imgur
{
    using Microsoft.Owin.Security;

    public class ImgurAuthenticationOptions : AuthenticationOptions
    {
        public ImgurAuthenticationOptions() : base(ImgurAuthenticationDefaults.AuthenticationType)
        {
        }
    }
}
