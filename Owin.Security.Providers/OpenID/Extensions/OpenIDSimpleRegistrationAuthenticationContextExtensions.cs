using System;
using System.Collections.Generic;
using System.Linq;

namespace Owin.Security.Providers.OpenID.Extensions
{
    /// <summary>
    /// Contains an extension method that makes reading the SREG fields easier.
    /// </summary>
    public static class OpenIDSimpleRegistrationAuthenticationContextExtensions
    {
        public static OpenIDSimpleRegistrationResult GetSimpleRegistrationResult(this OpenIDAuthenticatedContext context)
        {
            if (!context.ProtocolExtensionData.ContainsKey(typeof (OpenIDSimpleRegistrationExtension)))
            {
                return new OpenIDSimpleRegistrationResult();
            }
            else
            {
                return context.ProtocolExtensionData[typeof (OpenIDSimpleRegistrationExtension)] as OpenIDSimpleRegistrationResult;
            }
        }
    }
}