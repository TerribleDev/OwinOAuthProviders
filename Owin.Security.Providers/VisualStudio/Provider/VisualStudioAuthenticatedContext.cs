using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.VisualStudio {
	
	/// <summary>
	/// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
	/// </summary>
	public class VisualStudioAuthenticatedContext : BaseContext{

		/// <summary>
		/// Initializes a <see cref="VisualStudioAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Visual Studio Online Access token</param>
		public VisualStudioAuthenticatedContext(IOwinContext context, JObject user, string accessToken, int expiresIn, string refreshToken)
            : base(context)
        {
            AccessToken = accessToken;
            User = user;
			RefreshToken = refreshToken;
			ExpiresIn = TimeSpan.FromSeconds(expiresIn);

            Id = TryGetValue(user, "id");
			Name = TryGetValue(user, "displayName");
			Email = TryGetValue(user, "emailAddress");
			Alias = TryGetValue(user, "publicAlias");
        }

		/// <summary>
		/// Gets the JSON-serialized user
		/// </summary>
		/// <remarks>
		/// Contains the Visual Studio user obtained from the endpoint https://app.vssps.visualstudio.com/_apis/profile/profiles/me
		/// </remarks>
		public JObject User { get; private set; }

		/// <summary>
		/// Gets the Visual Studio Online OAuth access token
		/// </summary>
		public string AccessToken { get; private set; }

		/// <summary>
		/// Gets the Google OAuth refresh token.  This is only available when the RequestOfflineAccess property of <see cref="GooglePlusAuthenticationOptions"/> is set to true
		/// </summary>
		public string RefreshToken { get; private set; }

		/// <summary>
		/// Gets the Google+ access token expiration time
		/// </summary>
		public TimeSpan? ExpiresIn { get; set; }

		/// <summary>
		/// Get the user's id
		/// </summary>
		public string Id { get; private set; }

		/// <summary>
		/// Get the user's displayName
		/// </summary>
		public string Name { get; private set; }

		/// <summary>
		/// Get the user's email
		/// </summary>
		public string Email { get; private set; }

		/// <summary>
		/// Get the user's publicAlias
		/// </summary>
		public string Alias { get; private set; }

		/// <summary>
		/// Gets the <see cref="ClaimsIdentity"/> representing the user
		/// </summary>
		public ClaimsIdentity Identity { get; set; }

		/// <summary>
		/// Gets or sets a property bag for common authentication properties
		/// </summary>
		public AuthenticationProperties Properties { get; set; }

		private static string TryGetValue(JObject user, string propertyName) {
			JToken value;
			return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
		}
	}
}
