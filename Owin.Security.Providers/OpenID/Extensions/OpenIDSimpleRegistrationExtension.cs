using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Owin.Security.Providers.OpenID.Extensions
{
    /// <summary>
    /// Implements the OpenID Simple Registration Extension http://openid.net/specs/openid-simple-registration-extension-1_0.html
    /// </summary>
    public class OpenIDSimpleRegistrationExtension : IOpenIDProtocolExtension
    {

        private static readonly Dictionary<OpenIDSimpleRegistrationField, string> claimsMap = new Dictionary<OpenIDSimpleRegistrationField, string>()
        {
            { OpenIDSimpleRegistrationField.NickName, "nickname" },
            { OpenIDSimpleRegistrationField.FullName, "fullname" },
            { OpenIDSimpleRegistrationField.Email, "email" },
            { OpenIDSimpleRegistrationField.DayOfBirth, "dob" },
            { OpenIDSimpleRegistrationField.Gender, "gender" },
            { OpenIDSimpleRegistrationField.PostCode, "postcode" },
            { OpenIDSimpleRegistrationField.Country, "country" },
            { OpenIDSimpleRegistrationField.Language, "language" },
            { OpenIDSimpleRegistrationField.Timezone, "timezone" }
        };

        private const string sregNamespace = "http://openid.net/extensions/sreg/1.1";


        /// <summary>
        /// Gets or sets a list of comma-separated SREG fields that are required.
        /// </summary>
        public HashSet<OpenIDSimpleRegistrationField> RequiredFields { get; private set; }

        /// <summary>
        /// Gets or sets a list of comma-separated SREG fields that are optional.
        /// </summary>
        public HashSet<OpenIDSimpleRegistrationField> OptionalFields { get; private set; }

        /// <summary>
        /// Gets or sets the SREG policy URL.
        /// </summary>
        public string PolicyUrl { get; set; }


        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIDSimpleRegistrationExtension"/> class.
        /// </summary>
        public OpenIDSimpleRegistrationExtension()
        {
            RequiredFields = new HashSet<OpenIDSimpleRegistrationField>() { OpenIDSimpleRegistrationField.Email, OpenIDSimpleRegistrationField.FullName };
            OptionalFields = new HashSet<OpenIDSimpleRegistrationField>();
            PolicyUrl = string.Empty;
        }


        /// <summary>
        /// Appends the SREG required attributes to the request URL constructed on challenge.
        /// </summary>
        public Task OnChallengeAsync(Microsoft.Owin.Security.AuthenticationResponseChallenge challenge, OpenIDAuthorizationEndpointInfo endpoint)
        {
            endpoint.Url += "&openid.ns.sreg=" + Uri.EscapeDataString(sregNamespace);

            var requiredClaims = string.Join(",", RequiredFields.Select(f => claimsMap[f]));
            endpoint.Url += "&openid.sreg.required=" + Uri.EscapeDataString(requiredClaims);

            if (OptionalFields.Any())
            {
                var optionalClaims = string.Join(",", OptionalFields.Select(f => claimsMap[f]));
                endpoint.Url += "&openid.sreg.optional=" + Uri.EscapeDataString(optionalClaims);
            }

            if (!string.IsNullOrEmpty(PolicyUrl))
            {
                endpoint.Url += "&openid.sreg.policy_url=" + Uri.EscapeDataString(PolicyUrl);
            }

            return Task.FromResult(0);
        }

        /// <summary>
        /// Validates the authentication response message.
        /// </summary>
        public Task<bool> OnValidateMessageAsync(Infrastructure.Message message)
        {
            // no additional checks needed
            return Task.FromResult(true);
        }

        /// <summary>
        /// Extracts SREG attributes and returns the results.
        /// </summary>
        public Task<object> OnExtractResultsAsync(ClaimsIdentity identity, string claimedId, Infrastructure.Message message)
        {
            var result = new OpenIDSimpleRegistrationResult();
            foreach (var claim in claimsMap)
            {
                string value;
                if (message.TryGetValue(claim.Value + "." + sregNamespace, out value))
                {
                    result.Values.Add(claim.Key, value);
                }
            }

            return Task.FromResult((object)result);
        }
    }
}
