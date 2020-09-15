namespace Owin.Security.Providers.Ping.Messages
{
    using Newtonsoft.Json;
    public class AccsessToken
    {
        /// <summary>Gets or sets the access token.</summary>
        [JsonProperty(PropertyName = "access_token")]
        public string AccessToken { get; set; }

        /// <summary>Gets or sets the error.</summary>
        [JsonProperty(PropertyName = "error")]
        public string Error { get; set; }

        /// <summary>Gets or sets the error description.</summary>
        [JsonProperty(PropertyName = "error_description")]
        public string ErrorDescription { get; set; }

        /// <summary>Gets or sets the id token.</summary>
        [JsonProperty(PropertyName = "id_token")]
        public string IdToken { get; set; }

        /// <summary>Gets or sets the refresh token.</summary>
        [JsonProperty(PropertyName = "refresh_token")]
        public string RefreshToken { get; set; }

    }
}
