using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.BattleNet
{
	public class BattleNetAuthenticationHandler : AuthenticationHandler<BattleNetAuthenticationOptions>
	{

		private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
		private string tokenEndpoint = "https://eu.battle.net/oauth/token";
		private string accountUserIdEndpoint = "https://eu.api.battle.net/account/user/id";
		private string accountUserBattleTagEndpoint = "https://eu.api.battle.net/account/user/battletag";
		private string oauthAuthEndpoint = "https://eu.battle.net/oauth/authorize";

		private readonly ILogger logger;
		private readonly HttpClient httpClient;

		public BattleNetAuthenticationHandler(HttpClient httpClient, ILogger logger)
		{
			this.httpClient = httpClient;
			this.logger = logger;
		}

        protected override Task InitializeCoreAsync()
        {
            switch (Options.Region)
            {
                case Region.China:
                    tokenEndpoint = "https://cn.battle.net/oauth/token";
                    accountUserIdEndpoint = "https://cn.api.battle.net/account/user/id";
                    accountUserBattleTagEndpoint = "https://cn.api.battle.net/account/user/battletag";
                    oauthAuthEndpoint = "https://cn.battle.net/oauth/authorize";
                    break;
                case Region.Korea:
                    tokenEndpoint = "https://kr.battle.net/oauth/token";
                    accountUserIdEndpoint = "https://kr.api.battle.net/account/user/id";
                    accountUserBattleTagEndpoint = "https://kr.api.battle.net/account/user/battletag";
                    oauthAuthEndpoint = "https://kr.battle.net/oauth/authorize";
                    break;
                case Region.Taiwan:
                    tokenEndpoint = "https://tw.battle.net/oauth/token";
                    accountUserIdEndpoint = "https://tw.api.battle.net/account/user/id";
                    accountUserBattleTagEndpoint = "https://tw.api.battle.net/account/user/battletag";
                    oauthAuthEndpoint = "https://tw.battle.net/oauth/authorize";
                    break;
                case Region.Europe:
                    tokenEndpoint = "https://eu.battle.net/oauth/token";
                    accountUserIdEndpoint = "https://eu.api.battle.net/account/user/id";
                    accountUserBattleTagEndpoint = "https://eu.api.battle.net/account/user/battletag";
                    oauthAuthEndpoint = "https://eu.battle.net/oauth/authorize";
                    break;
                default:
                    tokenEndpoint = "https://us.battle.net/oauth/token";
                    accountUserIdEndpoint = "https://us.api.battle.net/account/user/id";
                    accountUserBattleTagEndpoint = "https://us.api.battle.net/account/user/battletag";
                    oauthAuthEndpoint = "https://us.battle.net/oauth/authorize";
                    break;
            }

            return Task.FromResult(true);
        }

		protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
		{
			AuthenticationProperties properties = null;

			try
			{
				string code = null;
				string state = null;

				var query = Request.Query;
				var values = query.GetValues("code");
				if (values != null && values.Count == 1)
				{
					code = values[0];
				}
				values = query.GetValues("state");
				if (values != null && values.Count == 1)
				{
					state = values[0];
				}

				properties = Options.StateDataFormat.Unprotect(state);
				if (properties == null)
				{
					return null;
				}

				// OAuth2 10.12 CSRF
				if (!ValidateCorrelationId(properties, logger))
				{
					return new AuthenticationTicket(null, properties);
				}

				// Check for error
				if (Request.Query.Get("error") != null)
					return new AuthenticationTicket(null, properties);

				var requestPrefix = Request.Scheme + "://" + Request.Host;
				var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

				// Build up the body for the token request
				var body = new List<KeyValuePair<string, string>>
				{
					new KeyValuePair<string, string>("grant_type", "authorization_code"),
					new KeyValuePair<string, string>("code", code),
					new KeyValuePair<string, string>("redirect_uri", redirectUri),
					new KeyValuePair<string, string>("client_id", Options.ClientId),
					new KeyValuePair<string, string>("client_secret", Options.ClientSecret)
				};

				// Request the token
				var tokenResponse = await httpClient.PostAsync(tokenEndpoint, new FormUrlEncodedContent(body));
				tokenResponse.EnsureSuccessStatusCode();
				var text = await tokenResponse.Content.ReadAsStringAsync();

				// Deserializes the token response
				var response = JsonConvert.DeserializeObject<dynamic>(text);
				var accessToken = (string)response.access_token;
				var expires = (string)response.expires_in;

				// Get WoW User Id
				var graphResponse = await httpClient.GetAsync(accountUserIdEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken), Request.CallCancelled);
				graphResponse.EnsureSuccessStatusCode();
				text = await graphResponse.Content.ReadAsStringAsync();
				var userId = JObject.Parse(text);

				// Get WoW BattleTag
				graphResponse = await httpClient.GetAsync(accountUserBattleTagEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken), Request.CallCancelled);
				graphResponse.EnsureSuccessStatusCode();
				text = await graphResponse.Content.ReadAsStringAsync();
				var battleTag = JObject.Parse(text);


				var context = new BattleNetAuthenticatedContext(Context, userId, battleTag, accessToken, expires)
				{
					Identity = new ClaimsIdentity(
						Options.AuthenticationType,
						ClaimsIdentity.DefaultNameClaimType,
						ClaimsIdentity.DefaultRoleClaimType)
				};

				if (!string.IsNullOrEmpty(context.Id))
				{
					context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType));
				}
				if (!string.IsNullOrEmpty(context.BattleTag))
				{
					context.Identity.AddClaim(new Claim("urn:battlenet:battletag", context.BattleTag, XmlSchemaString, Options.AuthenticationType));
				}
				if (!string.IsNullOrEmpty(context.AccessToken))
				{
					context.Identity.AddClaim(new Claim("urn:battlenet:accesstoken", context.AccessToken, XmlSchemaString, Options.AuthenticationType));
				}
				context.Properties = properties;

				await Options.Provider.Authenticated(context);

				return new AuthenticationTicket(context.Identity, context.Properties);

			}
			catch (Exception ex)
			{
				logger.WriteError(ex.Message);
			}
			return new AuthenticationTicket(null, properties);
		}

		protected override Task ApplyResponseChallengeAsync()
		{
			if (Response.StatusCode != 401)
			{
				return Task.FromResult<object>(null);
			}

			var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

			if (challenge != null)
			{
				var baseUri =
					Request.Scheme +
					Uri.SchemeDelimiter +
					Request.Host +
					Request.PathBase;

				var currentUri =
					baseUri +
					Request.Path +
					Request.QueryString;

				var redirectUri =
					baseUri +
					Options.CallbackPath;

				var properties = challenge.Properties;
				if (string.IsNullOrEmpty(properties.RedirectUri))
				{
					properties.RedirectUri = currentUri;
				}

				// OAuth2 10.12 CSRF
				GenerateCorrelationId(properties);

				// comma separated
				var scope = string.Join(" ", Options.Scope);

				var state = Options.StateDataFormat.Protect(properties);

				var authorizationEndpoint =
					oauthAuthEndpoint +
					"?response_type=code" +
					"&client_id=" + Uri.EscapeDataString(Options.ClientId) +
					"&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
					"&scope=" + Uri.EscapeDataString(scope) +
					"&state=" + Uri.EscapeDataString(state);

				Response.Redirect(authorizationEndpoint);
			}

			return Task.FromResult<object>(null);

			

		}

		public override async Task<bool> InvokeAsync()
		{

			return await InvokeReplyPathAsync();
			
		}

		private async Task<bool> InvokeReplyPathAsync()
		{
			if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
			{
				// TODO: error responses

				var ticket = await AuthenticateAsync();
				if (ticket == null)
				{
					logger.WriteWarning("Invalid return state, unable to redirect.");
					Response.StatusCode = 500;
					return true;
				}

				var context = new BattleNetReturnEndpointContext(Context, ticket)
				{
					SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
					RedirectUri = ticket.Properties.RedirectUri
				};

				await Options.Provider.ReturnEndpoint(context);

				if (context.SignInAsAuthenticationType != null &&
					context.Identity != null)
				{
					ClaimsIdentity grantIdentity = context.Identity;
					if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
					{
						grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
					}
					Context.Authentication.SignIn(context.Properties, grantIdentity);
				}

				if (!context.IsRequestCompleted && context.RedirectUri != null)
				{
					string redirectUri = context.RedirectUri;
					if (context.Identity == null)
					{
						// add a redirect hint that sign-in failed in some way
						redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
					}
					Response.Redirect(redirectUri);
					context.RequestCompleted();
				}

				return context.IsRequestCompleted;
			}
			return false;
		}
	}
}
