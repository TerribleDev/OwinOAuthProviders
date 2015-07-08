namespace Owin.Security.Providers.Imgur
{
    using System;
    using System.Net.Http;

    using Microsoft.Owin;
    using Microsoft.Owin.Security;

    using Owin.Security.Providers.Imgur.Provider;

    public class ImgurAuthenticationOptions : AuthenticationOptions
    {
        public ImgurAuthenticationOptions() : base(ImgurAuthenticationDefaults.AuthenticationType)
        {
            this.AuthenticationMode = AuthenticationMode.Passive;
            this.BackchannelTimeout = TimeSpan.FromSeconds(60);
            this.CallbackPath = new PathString("/signin-imgur");
            this.Caption = ImgurAuthenticationDefaults.AuthenticationType;
        }

        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        public TimeSpan BackchannelTimeout { get; set; }

        public PathString CallbackPath { get; set; }

        public string Caption { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public IImgurAuthenticationProvider Provider { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
    }
}
