#region

using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;

#endregion

namespace Owin.Security.Providers.Podbean
{
	/// <summary>
	///     Contains information about the login session as well as the user
	///     <see cref="System.Security.Claims.ClaimsIdentity" />.
	/// </summary>
	public class PodbeanAuthenticatedContext : BaseContext
	{
		/// <summary>
		///     Initializes a <see cref="PodbeanAuthenticatedContext" />
		/// </summary>
		/// <param name="context">The OWIN environment</param>
		/// <param name="podcast">The <see cref="Podcast"/></param>
		/// <param name="accessToken">Podbean Access token</param>
		/// <param name="refreshToken">Podbean Refresh token</param>
		/// <param name="expires">Seconds until expiration</param>
		public PodbeanAuthenticatedContext(IOwinContext context, Podcast podcast, string accessToken, string refreshToken, string expires)
			: base(context)
		{
			Podcast = podcast;
			Id = podcast.Id;
			Name = podcast.Title;
			AccessToken = accessToken;
			RefreshToken = refreshToken;

			int expiresValue;
			if (int.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
				ExpiresIn = TimeSpan.FromSeconds(expiresValue);
		}

		/// <summary>
		///     Gets the JSON-serialized user
		/// </summary>
		/// <remarks>
		///     Contains the Podbean user obtained from the endpoint https://api.Podbeanapp.com/1/user.json
		/// </remarks>
		public Podcast Podcast { get; }

		/// <summary>
		///     Gets the Podbean OAuth access token
		/// </summary>
		public string AccessToken { get; }

		/// <summary>
		///     Gets the Podbean OAuth refresh token
		/// </summary>
		public string RefreshToken { get; }

		/// <summary>
		///     Gets the Podbean access token expiration time
		/// </summary>
		public TimeSpan? ExpiresIn { get; set; }

		/// <summary>
		/// Gets the Podbean Podcast ID
		/// </summary>
		public string Id { get; }

		/// <summary>
		///     The name of the user
		/// </summary>
		public string Name { get; }

		/// <summary>
		///     Gets the <see cref="ClaimsIdentity" /> representing the user
		/// </summary>
		public ClaimsIdentity Identity { get; set; }

		/// <summary>
		///     Gets or sets a property bag for common authentication properties
		/// </summary>
		public AuthenticationProperties Properties { get; set; }
	}

	public class Podcast
	{
		/// <summary>
		/// The Id of the <see cref="Podcast"/>
		/// </summary>
		public string Id { get; set; }

		/// <summary>
		/// The title of the <see cref="Podcast"/>
		/// </summary>
		public string Title { get; set; }

		/// <summary>
		/// The description of the <see cref="Podcast"/>
		/// </summary>
		[JsonProperty(PropertyName = "desc")]
		public string Description { get; set; }

		/// <summary>
		/// A url to an image representing the logo of the <see cref="Podcast"/>
		/// </summary>
		public string Logo { get; set; }

		/// <summary>
		/// A url to the <see cref="Podcast"/>'s website
		/// </summary>
		public string Website { get; set; }

		/// <summary>
		/// The name of the category of the <see cref="Podcast"/>
		/// </summary>
		[JsonProperty(PropertyName = "category_name")]
		public string CategoryName { get; set; }

		/// <summary>
		/// The episode types of the <see cref="Podcast"/>.
		/// The possible value is a combination of public, premium or private
		/// </summary>
		[JsonProperty(PropertyName = "allow_episode_type")]
		public string[] AllowEpisodeTypes { get; set; }
	}

}