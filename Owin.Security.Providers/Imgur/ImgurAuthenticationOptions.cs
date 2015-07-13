namespace Owin.Security.Providers.Imgur
{
    using System;
    using System.Net.Http;

    using Microsoft.Owin;
    using Microsoft.Owin.Security;

    using Owin.Security.Providers.Imgur.Provider;

    /// <summary></summary>
    public class ImgurAuthenticationOptions : AuthenticationOptions
    {
        /// <summary></summary>
        public ImgurAuthenticationOptions()
            : base(ImgurAuthenticationDefaults.AuthenticationType)
        {
            this.AuthenticationMode = AuthenticationMode.Passive;
            this.BackchannelTimeout = TimeSpan.FromSeconds(60);
            this.CallbackPath = new PathString(ImgurAuthenticationDefaults.CallbackPath);
            this.Caption = ImgurAuthenticationDefaults.AuthenticationType;
        }

        /// <summary></summary>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary></summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary></summary>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary></summary>
        public PathString CallbackPath { get; set; }

        /// <summary></summary>
        public string Caption
        {
            get
            {
                return this.Description.Caption;
            }

            set
            {
                this.Description.Caption = value;
            }
        }

        /// <summary></summary>
        public string ClientId { get; set; }

        /// <summary></summary>
        public string ClientSecret { get; set; }

        /// <summary></summary>
        public IImgurAuthenticationProvider Provider { get; set; }

        /// <summary></summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary></summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
    }
}
