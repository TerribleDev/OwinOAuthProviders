namespace Owin.Security.Providers.Ping.Helper
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Claims;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.Owin;
    using Microsoft.Owin.Infrastructure;
    using Microsoft.Owin.Logging;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Infrastructure;
    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;
    using Owin.Security.Providers.Ping.Messages;
    using Owin.Security.Providers.Ping.Provider;
    public class PingAuthenticationHandlerHelper
    {
        /// <summary>The ping error code.</summary>
        private const string PingErrorCode = "error";

        /// <summary>The ping error description code.</summary>
        private const string PingErrorDescriptionCode = "error_description";

        public static Dictionary<string, string> MergeAdditionalKeyValuePairsIntoExplicitKeyValuePairs(
          Dictionary<string, string> explicitProperties,
          Dictionary<string, string> additionalProperties = null)
        {
            var merged = explicitProperties;

            // no need to iterate if additional is null
            if (additionalProperties != null)
            {
                merged = explicitProperties.Concat(additionalProperties.Where(add => !explicitProperties.ContainsKey(add.Key)))
                        .Where(a => !string.IsNullOrEmpty(a.Value))
                        .ToDictionary(final => final.Key, final => final.Value);
            }

            return merged;
        }

        /// <summary>Detects if the request has error messages in the form of 'error' and 'error_description'</summary>
        /// <param name="request">The OWIN request.</param>
        /// <param name="error">Output parameter with the code of the error.</param>
        /// <param name="errorDescription">Output parameter with the error description.</param>
        /// <returns>The <see cref="bool"/>.</returns>
        public static bool RequestHasErrorMessages(IOwinRequest request, out string error, out string errorDescription)
        {
            if (request == null)
            {
                throw new ArgumentNullException("request");
            }

            error = null;
            errorDescription = null;
            var query = request.Query;
            var values = query.GetValues(PingErrorCode);
            if (values != null && values.Count == 1)
            {
                error = values[0];
            }

            values = query.GetValues(PingErrorDescriptionCode);
            if (values != null && values.Count == 1)
            {
                errorDescription = values[0];
            }

            return !string.IsNullOrEmpty(error) || !string.IsNullOrEmpty(errorDescription);
        }

        /// <summary>The encode credential.</summary>
        /// <param name="userName">The user name.</param>
        /// <param name="password">The password.</param>
        /// <returns>The <see cref="string"/>.</returns>
        /// TODO : Move to Helper
        public static string EncodeCredential(string userName, string password)
        {
            var encoding = Encoding.GetEncoding("iso-8859-1");
            var credential = string.Format(CultureInfo.InvariantCulture, "{0}:{1}", userName, password);
            return Convert.ToBase64String(encoding.GetBytes(credential));
        }

        public static void EnsureAcceptedNetwork(string[] validNetworks, string userNetwork)
        {
            if (validNetworks == null || validNetworks.Length <= 0) return;
            var isValid = validNetworks.Any(network => userNetwork == network);
            if (!isValid) throw new Exception("User is not in list of accepted networks");
        }


    }
}
