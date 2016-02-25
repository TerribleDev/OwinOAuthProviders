using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Orcid.Message
{
    public static class OrcidMessageExtensions
    {
        public static OrcidAuthenticatedContext ToAuthenticationContext(this string json, IOwinContext context, string accessToken)
        {
            var profile = JsonConvert.DeserializeObject<OrcidProfileMessage>(json);

            var user = JObject.Parse(json);

            var authenticatedContext = new OrcidAuthenticatedContext(context, user, accessToken);

            var email = profile.OrcidProfile.OrcidBio.ContactDetails.Email.LastOrDefault();
            if (email != null)
                authenticatedContext.Email = email.Value;

            authenticatedContext.FirstName = profile.OrcidProfile.OrcidBio.PersonalDetails.GivenNames.Value;
            authenticatedContext.LastName = profile.OrcidProfile.OrcidBio.PersonalDetails.FamilyName.Value;

            return authenticatedContext;
        }
    }
}
