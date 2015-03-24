// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.BattleNet
{
	/// <summary>
	/// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
	/// </summary>
	public class BattleNetAuthenticatedContext : BaseContext
	{
		/// <summary>
		/// Initializes a <see cref="BattleNetAuthenticatedContext"/>
		/// </summary>
		/// <param name="context">The OWIN environment</param>
		/// <param name="userId">The JSON-serialized userId</param>
		/// <param name="battleTag">The JSON-serialized battleTag</param>
		/// <param name="accessToken">Battle.net Access token</param>
		/// <param name="expires">Seconds until expiration</param>
		public BattleNetAuthenticatedContext(IOwinContext context, JObject userId, JObject battleTag, string accessToken, string expires)
			: base(context)
		{
			JsonUserId = userId;
			JsonBattleTag = battleTag;
			AccessToken = accessToken;

			int expiresValue;
			if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
			{
				ExpiresIn = TimeSpan.FromSeconds(expiresValue);
			}

			Id = TryGetValue(userId, "id");
			BattleTag = TryGetValue(battleTag, "battletag");

		}

		/// <summary>
		/// Gets the JSON-serialized user ID
		/// </summary>
		/// <remarks>
		/// Contains the Battle.net user ID obtained from the endpoint https://eu.api.battle.net/account/user/id
		/// </remarks>
		public JObject JsonUserId { get; private set; }

		/// <summary>
		/// Gets the JSON-serialized BattleTag
		/// </summary>
		/// <remarks>
		/// Contains the Battle.net battle tag obtained from the endpoint https://eu.api.battle.net/account/user/battletag.  For more information
		/// see https://dev.battle.net/io-docs
		/// </remarks>
		public JObject JsonBattleTag { get; private set; }

		/// <summary>
		/// Gets the Battle.net OAuth access token
		/// </summary>
		public string AccessToken { get; private set; }

		/// <summary>
		/// Gets the Battle.net access token expiration time
		/// </summary>
		public TimeSpan? ExpiresIn { get; set; }

		/// <summary>
		/// Gets the Battle.net user ID
		/// </summary>
		public string Id { get; private set; }

		/// <summary>
		/// Get Wow users battle tag
		/// </summary>
		public string BattleTag { get; private set; }

		/// <summary>
		/// Gets the <see cref="ClaimsIdentity"/> representing the user
		/// </summary>
		public ClaimsIdentity Identity { get; set; }

		/// <summary>
		/// Gets or sets a property bag for common authentication properties
		/// </summary>
		public AuthenticationProperties Properties { get; set; }

		private static string TryGetValue(JObject user, string propertyName)
		{
			JToken value;
			return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
		}
	}
}