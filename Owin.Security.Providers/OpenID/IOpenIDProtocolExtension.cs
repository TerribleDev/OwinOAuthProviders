using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.OpenID
{
    public interface IOpenIDProtocolExtension
    {

        /// <summary>
        /// Adds the required information in the authorization endpoint URL.
        /// </summary>
        Task OnChallengeAsync(AuthenticationResponseChallenge challenge, OpenIDAuthorizationEndpointInfo endpoint);

        /// <summary>
        /// Performs additional authentication response message validations.
        /// </summary>
        Task<bool> OnValidateMessageAsync(Infrastructure.Message message);

        /// <summary>
        /// Extracts the data form the authentication response message and returns them.
        /// </summary>
        Task<object> OnExtractResultsAsync(System.Security.Claims.ClaimsIdentity identity, string claimedId, Infrastructure.Message message);
    }
}