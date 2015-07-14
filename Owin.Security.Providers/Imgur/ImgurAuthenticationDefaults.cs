namespace Owin.Security.Providers.Imgur
{
    /// <summary>Configuration strings for the imgur provider.</summary>
    internal static class ImgurAuthenticationDefaults
    {
        /// <summary>The error message for user authentication failure.</summary>
        internal const string AccessDeniedErrorMessage = "access_denied";

        /// <summary>The name of the access token property in the imgur authentication response.</summary>
        internal const string AccessTokenPropertyName = "access_token";

        /// <summary>The name of the account id property in the imgur authentication response.</summary>
        internal const string AccountIdPropertyName = "account_id";

        /// <summary>The name of the account username property in the imgur authentication response.</summary>
        internal const string AccountUsernamePropertyName = "account_username";

        /// <summary>The name of the provider.</summary>
        internal const string AuthenticationType = "Imgur";

        /// <summary>The grant type to be used.</summary>
        internal const string AuthorizationCodeGrantType = "authorization_code";

        /// <summary>The user authorization endpoint URL.</summary>
        internal const string AuthorizationUrl = "https://api.imgur.com/oauth2/authorize";

        /// <summary>The default callback path.</summary>
        internal const string CallbackPath = "/signin-imgur";

        /// <summary>The name of the application client id parameter.</summary>
        internal const string ClientIdParameter = "client_id";

        /// <summary>The name of the application client secret parameter.</summary>
        internal const string ClientSecretParameter = "client_secret";

        /// <summary>The name of the response code parameter.</summary>
        internal const string CodeParameter = "code";

        /// <summary>The code type of the authentication response.</summary>
        internal const string CodeResponseType = "code";

        /// <summary>The message for the communication failure error.</summary>
        internal const string CommunicationFailureMessage = "An error occurred while talking with imgur's server.";

        /// <summary>The message for the authentication response deserialization failure error.</summary>
        internal const string DeserializationFailureMessage = "The deserialization of the imgur's response failed. Perhaps imgur changed the response format?";

        /// <summary>The name of the error parameter.</summary>
        internal const string ErrorParameter = "error";

        /// <summary>The name of the access token duration property in the imgur authentication response.</summary>
        internal const string ExpiresInPropertyName = "expires_in";

        /// <summary>The name of the grant type parameter.</summary>
        internal const string GrantTypeParameter = "grant_type";

        /// <summary>The format to use to stringify <see cref="System.Int32"/>s.</summary>
        internal const string Int32Format = "D";

        /// <summary>The message for the invalid authentication ticket error.</summary>
        internal const string InvalidAuthenticationTicketMessage = "Invalid authentication ticket.";

        /// <summary>The name of the refresh token property in the imgur authentication response.</summary>
        internal const string RefreshInPropertyName = "refresh_token";

        /// <summary>The name of the response type parameter.</summary>
        internal const string ResponseTypeParameter = "response_type";

        /// <summary>The name of the scope property in the imgur authentication response.</summary>
        internal const string ScopePropertyName = "scope";

        /// <summary>The name of the state parameter.</summary>
        internal const string StateParameter = "state";

        /// <summary>The name of the token type property in the imgur authentication response.</summary>
        internal const string TokenTypePropertyName = "token_type";

        /// <summary>The token exchange endpoint URL.</summary>
        internal const string TokenUrl = "https://api.imgur.com/oauth2/token";

        /// <summary>The version of the provider.</summary>
        internal const string Version = "v1";

        /// <summary>The string value type for <see cref="System.Security.Claims.Claim"/>s.</summary>
        internal const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
    }
}
