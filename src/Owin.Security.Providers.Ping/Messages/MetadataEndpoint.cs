namespace Owin.Security.Providers.Ping.Messages
{
    using System.Collections.ObjectModel;
    using System.Diagnostics.CodeAnalysis;
    using Newtonsoft.Json;

    /// <summary>The metadata endpoints.</summary>
    public class MetadataEndpoint
    {
        #region Public Properties

        /// <summary>Gets or sets the authorization endpoint.</summary>
        [JsonProperty(PropertyName = "authorization_endpoint")]
        public string AuthorizationEndpoint { get; set; }

        /// <summary>Gets or sets the claim types supported.</summary>
        [SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly", Justification = "Required for deserialization")]
        [JsonProperty(PropertyName = "claim_types_supported")]
        public Collection<string> ClaimTypesSupported { get; set; }

        /// <summary>Gets or sets a value indicating whether claims parameter supported.</summary>
        [JsonProperty(PropertyName = "claims_parameter_supported")]
        public bool ClaimsParameterSupported { get; set; }

        /// <summary>Gets or sets the id token signing algorithms values supported.</summary>
        [SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly", Justification = "Required for deserialization")]
        [JsonProperty(PropertyName = "id_token_signing_alg_values_supported")]
        public Collection<string> IdTokenSigningAlgorithmValuesSupported { get; set; }

        /// <summary>Gets or sets the issuer.</summary>
        [JsonProperty(PropertyName = "issuer")]
        public string Issuer { get; set; }

        /// <summary>Gets or sets the JWKS URI.</summary>
        [JsonProperty(PropertyName = "jwks_uri")]
        public string JsonWebKeysUri { get; set; }

        /// <summary>Gets or sets the ping end session endpoint.</summary>
        [JsonProperty(PropertyName = "ping_end_session_endpoint")]
        public string PingEndSessionEndpoint { get; set; }

        /// <summary>Gets or sets the ping revoked SRIS endpoint.</summary>
        [JsonProperty(PropertyName = "ping_revoked_sris_endpoint")]
        public string PingRevokedSrisEndpoint { get; set; }

        /// <summary>Gets or sets a value indicating whether request parameter supported.</summary>
        [JsonProperty(PropertyName = "request_parameter_supported")]
        public bool RequestParameterSupported { get; set; }

        /// <summary>Gets or sets a value indicating whether request uri parameter supported.</summary>
        [JsonProperty(PropertyName = "request_uri_parameter_supported")]
        public bool RequestUriParameterSupported { get; set; }

        /// <summary>Gets or sets the response modes supported.</summary>
        [JsonProperty(PropertyName = "response_modes_supported")]
        public string[] ResponseModesSupported { get; set; }

        /// <summary>Gets or sets the response types supported.</summary>
        [SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly", Justification = "Required for deserialization")]
        [JsonProperty(PropertyName = "response_types_supported")]
        public Collection<string> ResponseTypesSupported { get; set; }

        /// <summary>Gets or sets the revocation endpoint.</summary>
        [JsonProperty(PropertyName = "revocation_endpoint")]
        public string RevocationEndpoint { get; set; }

        /// <summary>Gets or sets the scopes supported.</summary>
        [SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly", Justification = "Required for deserialization")]
        [JsonProperty(PropertyName = "scopes_supported")]
        public Collection<string> ScopesSupported { get; set; }

        /// <summary>Gets or sets the subject types supported.</summary>
        [SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly", Justification = "Required for deserialization")]
        [JsonProperty(PropertyName = "subject_types_supported")]
        public Collection<string> SubjectTypesSupported { get; set; }

        /// <summary>Gets or sets the token endpoint.</summary>
        [JsonProperty(PropertyName = "token_endpoint")]
        public string TokenEndpoint { get; set; }

        /// <summary>Gets or sets the token endpoint authentication methods supported.</summary>
        [SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly", Justification = "Required for deserialization")]
        [JsonProperty(PropertyName = "token_endpoint_auth_methods_supported")]
        public Collection<string> TokenEndpointAuthMethodsSupported { get; set; }

        /// <summary>Gets or sets the user info endpoint.</summary>
        [JsonProperty(PropertyName = "userinfo_endpoint")]
        public string UserInfoEndpoint { get; set; }

        /// <summary>Gets or sets the version.</summary>
        [JsonProperty(PropertyName = "version")]
        public string Version { get; set; }

        #endregion
    }
}
