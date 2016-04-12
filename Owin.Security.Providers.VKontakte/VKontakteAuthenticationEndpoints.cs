namespace Owin.Security.Providers.VKontakte
{
    public class VKontakteAuthenticationEndpoints
    {
        /// <summary>
        /// Endpoint which is used to redirect users to request VK access
        /// </summary>
        /// <remarks>
        /// Defaults to https://oauth.vk.com/authorize
        /// </remarks>
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Endpoint which is used to exchange code for access token
        /// </summary>
        /// <remarks>
        /// Defaults to https://oauth.vk.com/access_token
        /// </remarks>
        public string TokenEndpoint { get; set; }

        /// <summary>
        /// Endpoint which is used to obtain user information after authentication
        /// </summary>
        /// <remarks>
        /// Defaults to https://api.vk.com/method/users.get
        /// </remarks>
        public string UserInfoEndpoint { get; set; }
    }
}