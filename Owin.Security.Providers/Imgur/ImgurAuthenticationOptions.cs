namespace Owin.Security.Providers.Imgur
{
    using System;
    using System.Net.Http;

    using Microsoft.Owin;
    using Microsoft.Owin.Security;

    using Owin.Security.Providers.Imgur.Provider;

    /// <summary>Configuration options for the <see cref="ImgurAuthenticationMiddleware"/>.</summary>
    public class ImgurAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>Creates a new <see cref="ImgurAuthenticationOptions"/>.</summary>
        public ImgurAuthenticationOptions()
            : base(ImgurAuthenticationDefaults.AuthenticationType)
        {
            this.AuthenticationMode = AuthenticationMode.Passive;
            this.BackchannelTimeout = TimeSpan.FromSeconds(60);
            this.CallbackPath = new PathString(ImgurAuthenticationDefaults.CallbackPath);
            this.Caption = ImgurAuthenticationDefaults.AuthenticationType;
        }

        /// <summary>Gets or sets the a pinned certificate validator to use to validate the endpoints used in back channel communications belong to StackExchange.</summary>
        /// <remarks>If this property is null then the default certificate checks are performed, validating the subject name and if the signing chain is a trusted party.</remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>The HttpMessageHandler used to communicate with StackExchange.</summary>
        /// <remarks>This cannot be set at the same time as BackchannelCertificateValidator unless the value can be downcast to a WebRequestHandler.</remarks>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>Gets or sets timeout value in milliseconds for back channel communications with imgur.</summary>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>The request path within the application's base path where the user-agent will be returned. The middleware will process this request when it arrives.</summary>
        /// <remarks>The default value is "/signin-imgur".</remarks>
        public PathString CallbackPath { get; set; }

        /// <summary>Get or sets the text that the user can display on a sign in user interface.</summary>
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

        /// <summary>Gets or sets the imgur application client id.</summary>
        public string ClientId { get; set; }

        /// <summary>Gets or sets the imgur application client secret.</summary>
        public string ClientSecret { get; set; }

        /// <summary>Gets or sets the <see cref="IImgurAuthenticationProvider" /> used in the authentication events.</summary>
        public IImgurAuthenticationProvider Provider { get; set; }

        /// <summary>Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user.</summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary> Gets or sets the type used to secure the data handled by the middleware.</summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
    }
}
