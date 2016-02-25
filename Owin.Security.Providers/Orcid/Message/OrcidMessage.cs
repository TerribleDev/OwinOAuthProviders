using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Owin.Security.Providers.Orcid.Message
{
    public class OrcidIdentifier
    {

        [JsonProperty("value")]
        public object Value { get; set; }

        [JsonProperty("uri")]
        public string Uri { get; set; }

        [JsonProperty("path")]
        public string Path { get; set; }

        [JsonProperty("host")]
        public string Host { get; set; }
    }

    public class OrcidPreferences
    {

        [JsonProperty("locale")]
        public string Locale { get; set; }
    }

    public class SubmissionDate
    {

        [JsonProperty("value")]
        public long Value { get; set; }
    }

    public class LastModifiedDate
    {

        [JsonProperty("value")]
        public long Value { get; set; }
    }

    public class Claimed
    {

        [JsonProperty("value")]
        public bool Value { get; set; }
    }

    public class VerifiedEmail
    {

        [JsonProperty("value")]
        public bool Value { get; set; }
    }

    public class VerifiedPrimaryEmail
    {

        [JsonProperty("value")]
        public bool Value { get; set; }
    }

    public class OrcidHistory
    {

        [JsonProperty("creation-method")]
        public string CreationMethod { get; set; }

        [JsonProperty("completion-date")]
        public object CompletionDate { get; set; }

        [JsonProperty("submission-date")]
        public SubmissionDate SubmissionDate { get; set; }

        [JsonProperty("last-modified-date")]
        public LastModifiedDate LastModifiedDate { get; set; }

        [JsonProperty("claimed")]
        public Claimed Claimed { get; set; }

        [JsonProperty("source")]
        public object Source { get; set; }

        [JsonProperty("deactivation-date")]
        public object DeactivationDate { get; set; }

        [JsonProperty("verified-email")]
        public VerifiedEmail VerifiedEmail { get; set; }

        [JsonProperty("verified-primary-email")]
        public VerifiedPrimaryEmail VerifiedPrimaryEmail { get; set; }

        [JsonProperty("visibility")]
        public object Visibility { get; set; }
    }

    public class GivenNames
    {

        [JsonProperty("value")]
        public string Value { get; set; }

        [JsonProperty("visibility")]
        public object Visibility { get; set; }
    }

    public class FamilyName
    {

        [JsonProperty("value")]
        public string Value { get; set; }

        [JsonProperty("visibility")]
        public object Visibility { get; set; }
    }

    public class OtherNames
    {

        [JsonProperty("other-name")]
        public object[] OtherName { get; set; }

        [JsonProperty("visibility")]
        public string Visibility { get; set; }
    }

    public class PersonalDetails
    {

        [JsonProperty("given-names")]
        public GivenNames GivenNames { get; set; }

        [JsonProperty("family-name")]
        public FamilyName FamilyName { get; set; }

        [JsonProperty("credit-name")]
        public object CreditName { get; set; }

        [JsonProperty("other-names")]
        public OtherNames OtherNames { get; set; }
    }

    public class Biography
    {

        [JsonProperty("value")]
        public object Value { get; set; }

        [JsonProperty("visibility")]
        public string Visibility { get; set; }
    }

    public class ResearcherUrls
    {

        [JsonProperty("researcher-url")]
        public object[] ResearcherUrl { get; set; }

        [JsonProperty("visibility")]
        public string Visibility { get; set; }
    }

    public class Email
    {

        [JsonProperty("value")]
        public string Value { get; set; }

        [JsonProperty("primary")]
        public bool Primary { get; set; }

        [JsonProperty("current")]
        public bool Current { get; set; }

        [JsonProperty("verified")]
        public bool Verified { get; set; }

        [JsonProperty("visibility")]
        public string Visibility { get; set; }

        [JsonProperty("source")]
        public string Source { get; set; }

        [JsonProperty("source-client-id")]
        public object SourceClientId { get; set; }
    }

    public class ContactDetails
    {

        [JsonProperty("email")]
        public Email[] Email { get; set; }

        [JsonProperty("address")]
        public object Address { get; set; }
    }

    public class ExternalIdentifiers
    {

        [JsonProperty("external-identifier")]
        public object[] ExternalIdentifier { get; set; }

        [JsonProperty("visibility")]
        public string Visibility { get; set; }
    }

    public class OrcidBio
    {

        [JsonProperty("personal-details")]
        public PersonalDetails PersonalDetails { get; set; }

        [JsonProperty("biography")]
        public Biography Biography { get; set; }

        [JsonProperty("researcher-urls")]
        public ResearcherUrls ResearcherUrls { get; set; }

        [JsonProperty("contact-details")]
        public ContactDetails ContactDetails { get; set; }

        [JsonProperty("keywords")]
        public object Keywords { get; set; }

        [JsonProperty("external-identifiers")]
        public ExternalIdentifiers ExternalIdentifiers { get; set; }

        [JsonProperty("delegation")]
        public object Delegation { get; set; }

        [JsonProperty("scope")]
        public object Scope { get; set; }
    }

    public class OrcidProfile
    {

        [JsonProperty("orcid")]
        public object Orcid { get; set; }

        [JsonProperty("orcid-id")]
        public object OrcidId { get; set; }

        [JsonProperty("orcid-identifier")]
        public OrcidIdentifier OrcidIdentifier { get; set; }

        [JsonProperty("orcid-deprecated")]
        public object OrcidDeprecated { get; set; }

        [JsonProperty("orcid-preferences")]
        public OrcidPreferences OrcidPreferences { get; set; }

        [JsonProperty("orcid-history")]
        public OrcidHistory OrcidHistory { get; set; }

        [JsonProperty("orcid-bio")]
        public OrcidBio OrcidBio { get; set; }

        [JsonProperty("orcid-activities")]
        public object OrcidActivities { get; set; }

        [JsonProperty("orcid-internal")]
        public object OrcidInternal { get; set; }

        [JsonProperty("type")]
        public string Type { get; set; }

        [JsonProperty("group-type")]
        public object GroupType { get; set; }

        [JsonProperty("client-type")]
        public object ClientType { get; set; }
    }

    public class OrcidProfileMessage
    {

        [JsonProperty("message-version")]
        public string MessageVersion { get; set; }

        [JsonProperty("orcid-profile")]
        public OrcidProfile OrcidProfile { get; set; }

        [JsonProperty("error-desc")]
        public object ErrorDesc { get; set; }
    }
}
