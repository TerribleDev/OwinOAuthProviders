using System;
using System.Globalization;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.Cosign.Provider;
using Owin.Security.Providers.Properties;

namespace Owin.Security.Providers.Cosign
{
    public class CosignAuthenticationMiddleware : AuthenticationMiddleware<CosignAuthenticationOptions>
    {
        private readonly ILogger logger;
        public CosignAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, CosignAuthenticationOptions options)
            : base(next, options)
        {
            if (String.IsNullOrWhiteSpace(Options.ClientServer))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "ClientServer"));
            if (String.IsNullOrWhiteSpace(Options.CosignServer))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "CosignServer"));
            if ((Options.CosignServicePort==0))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "CosignServicePort"));


            logger = app.CreateLogger<CosignAuthenticationMiddleware>();
            logger.WriteInformation("CosignAthenticationMiddleware has been created");
            if (Options.Provider == null)
                Options.Provider = new CosignAuthenticationProvider();

            if (string.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }
            if (options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof (CosignAuthenticationMiddleware).FullName,
                    options.AuthenticationType);

                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }



        }


        protected override AuthenticationHandler<CosignAuthenticationOptions> CreateHandler()
        {
            return new CosignAuthenticationHandler(logger);
        }
    }
}