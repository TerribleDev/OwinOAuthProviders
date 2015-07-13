namespace Owin.Security.Providers.Imgur
{
    /// <summary></summary>
    internal static class ImgurAuthenticationDefaults
    {
        /// <summary></summary>
        internal const string AccessDeniedErrorMessage = "access_denied";

        /// <summary></summary>
        internal const string AccessTokenPropertyName = "access_token";

        /// <summary></summary>
        internal const string AccountIdPropertyName = "account_id";

        /// <summary></summary>
        internal const string AccountUsernamePropertyName = "account_username";

        /// <summary></summary>
        internal const string AuthenticationType = "Imgur";

        /// <summary></summary>
        internal const string AuthorizationCodeGrantType = "authorization_code";

        /// <summary></summary>
        internal const string AuthorizationUri = "https://api.imgur.com/oauth2/authorize";

        /// <summary></summary>
        internal const string CallbackPath = "/signin-imgur";

        /// <summary></summary>
        internal const string ClientIdParameter = "client_id";

        /// <summary></summary>
        internal const string ClientSecretParameter = "client_secret";

        /// <summary></summary>
        internal const string CodeParameter = "code";

        /// <summary></summary>
        internal const string CodeResponseType = "code";

        /// <summary></summary>
        internal const string CommunicationFailureMessage = "An error occurred while talking with imgur's server.";

        /// <summary></summary>
        internal const string DeserializationFailureMessage = "The deserialization of the imgur's response failed. Perhaps imgur changed the response format?";

        /// <summary></summary>
        internal const string ErrorParameter = "error";

        /// <summary></summary>
        internal const string ExpiresInPropertyName = "expires_in";

        /// <summary></summary>
        internal const string GrantTypeParameter = "grant_type";

        /// <summary></summary>
        internal const string Int32Format = "D";

        /// <summary></summary>
        internal const string InvalidAuthenticationTicketMessage = "Invalid authentication ticket.";

        /// <summary></summary>
        internal const string RefreshInPropertyName = "refresh_token";

        /// <summary></summary>
        internal const string ResponseTypeParameter = "response_type";

        /// <summary></summary>
        internal const string ScopePropertyName = "scope";

        /// <summary></summary>
        internal const string StateParameter = "state";

        /// <summary></summary>
        internal const string TokenTypePropertyName = "token_type";

        /// <summary></summary>
        internal const string TokenUri = "https://api.imgur.com/oauth2/token";

        /// <summary></summary>
        internal const string Version = "v1";

        /// <summary></summary>
        internal const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
    }
}
