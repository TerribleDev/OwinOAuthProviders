namespace Owin.Security.Providers.Imgur
{
    internal static class ImgurAuthenticationDefaults
    {
        internal const string AccessDeniedErrorMessage = "access_denied";
        internal const string AccessTokenPropertyName = "access_token";
        internal const string AccountIdPropertyName = "account_id";
        internal const string AccountUsernamePropertyName = "account_username";
        internal const string AuthenticationType = "Imgur";
        internal const string AuthorizationCodeGrantType = "authorization_code";
        internal const string AuthorizationUri = "https://api.imgur.com/oauth2/authorize";
        internal const string CallbackPath = "/signin-imgur";
        internal const string ClientIdParameter = "client_id";
        internal const string ClientSecretParameter = "client_secret";
        internal const string CodeParameter = "code";
        internal const string CodeResponseType = "code";
        internal const string CommunicationFailureMessage = "An error occurred while talking with imgur's server.";
        internal const string DeserializationFailureMessage = "The deserialization of the imgur's response failed. Perhaps imgur changed the response format?";
        internal const string ErrorParameter = "error";
        internal const string ExpiresInPropertyName = "expires_in";
        internal const string GrantTypeParameter = "grant_type";
        internal const string Int32Format = "D";
        internal const string InvalidAuthenticationTicketMessage = "Invalid authentication ticket.";
        internal const string RefreshInPropertyName = "refresh_token";
        internal const string ResponseTypeParameter = "response_type";
        internal const string ScopePropertyName = "scope";
        internal const string StateParameter = "state";
        internal const string TokenTypePropertyName = "token_type";
        internal const string TokenUri = "https://api.imgur.com/oauth2/token";
        internal const string Version = "v1";
        internal const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
    }
}
