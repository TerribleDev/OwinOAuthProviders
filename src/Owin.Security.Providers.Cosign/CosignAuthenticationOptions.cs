using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.Providers.Cosign.Provider;

namespace Owin.Security.Providers.Cosign
{
    public class CosignAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-cosign".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        ///     Gets or sets the Cosgin server
        /// </summary>
        public string CosignServer { get; set; }

        /// <summary>
        ///     Gets or sets the instance of Identity Server Host
        /// </summary>
        public string IdentityServerHostInstance { get; set; }


        /// <summary>
        ///     Gets or sets the Cosign service name
        /// </summary>
        public string ClientServer { get; set; }

        /// <summary>
        ///     Gets or sets the Cosign service port
        /// </summary>
        public int CosignServicePort { get; set; }

        /// <summary>
        ///     Gets or sets the <see cref="ICosignAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public ICosignAuthenticationProvider Provider { get; set; }



        /// <summary>
        ///     Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user
        ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        ///     Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        ///     Initializes a new <see cref="CosignAuthenticationOptions" />
        /// </summary>
        public CosignAuthenticationOptions(): base("Cosign")
        {
            //CosignServer = cosignServer;
            //ClientServer = clientServer;
            Description.Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-cosign");
            AuthenticationMode = AuthenticationMode.Passive;
            IdentityServerHostInstance = "";

        }
    }
}