namespace Owin.Security.Providers.Ping.Provider
{
    using System.Security.Claims;
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;
    using Newtonsoft.Json.Linq;

    public class PingAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="PingAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Ping Access token</param>
        public PingAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string identityToken, string refreshToken) : base(context)
        {
            this.User = user;
            this.AccessToken = accessToken;
            this.IdentityToken = identityToken;
            this.RefreshToken = refreshToken;
            this.Id = TryGetValue(user, "sub");
            this.Name = TryGetValue(user, "name");
            this.Preferred_Username = TryGetValue(user, "preferred_username");
            this.Email = TryGetValue(user, "email");
            this.UserName = TryGetValue(user, "preferred_username");
        }

        public string UserName { get; set; }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Ping user
        /// </remarks>
        public dynamic User { get; private set; }

        /// <summary>
        /// Gets the Ping access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Ping user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the Ping full_name
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// Gets the Ping url
        /// </summary>
        public string Url { get; private set; }

        /// <summary>
        /// Gets the Primary Email
        /// </summary>
        public string PrimaryEmail { get; private set; }

        /// <summary>
        /// Gets the network_name
        /// </summary>
        public string Network { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        public string IdentityToken { get; set; }

        public string RefreshToken { get; set; }

        /// <summary>
        /// TODO : Move to Helper File
        /// </summary>
        /// <param name="user"></param>
        /// <param name="propertyName"></param>
        /// <returns></returns>
        private static string TryGetValue(JObject user, string propertyName)
        {
            if (user == null)
            {
                return null;
            }

            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }

        public string Preferred_Username { get; set; }

        public string Email { get; set; }
    }
}
