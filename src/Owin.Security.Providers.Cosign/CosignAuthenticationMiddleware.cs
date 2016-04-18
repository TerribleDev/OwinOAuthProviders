using System;
using System.Globalization;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.Cosign.Provider;

namespace Owin.Security.Providers.Cosign
{
    public class CosignAuthenticationMiddleware : AuthenticationMiddleware<CosignAuthenticationOptions>
    {
        private readonly ILogger _logger;
        public CosignAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, CosignAuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(Options.ClientServer))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "ClientServer"));
            if (string.IsNullOrWhiteSpace(Options.CosignServer))
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "CosignServer"));
            if (Options.CosignServicePort==0)
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture,
                    Resources.Exception_OptionMustBeProvided, "CosignServicePort"));


            _logger = app.CreateLogger<CosignAuthenticationMiddleware>();
            _logger.WriteInformation("CosignAuthenticationMiddleware has been created");
            if (Options.Provider == null)
                Options.Provider = new CosignAuthenticationProvider();

            if (string.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }
            if (options.StateDataFormat != null) return;
            var dataProtector = app.CreateDataProtector(typeof (CosignAuthenticationMiddleware).FullName,
                options.AuthenticationType);

            options.StateDataFormat = new PropertiesDataFormat(dataProtector);
        }


        protected override AuthenticationHandler<CosignAuthenticationOptions> CreateHandler()
        {
            return new CosignAuthenticationHandler(_logger);
        }
    }
}