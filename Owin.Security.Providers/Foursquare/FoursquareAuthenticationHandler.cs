using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using Owin.Security.Providers.Foursquare.Provider;

namespace Owin.Security.Providers.Foursquare
{
	public class FoursquareAuthenticationHandler : AuthenticationHandler<FoursquareAuthenticationOptions>
	{
		private const String AuthorizationEndpoint = "https://foursquare.com/oauth2/authenticate";
		private const String TokenEndpoint = "https://foursquare.com/oauth2/access_token";
		private const String GraphApiEndpoint = "https://api.foursquare.com/v2/users/self";
		private const String XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

		private readonly ILogger _logger;
		private readonly HttpClient _httpClient;

		public FoursquareAuthenticationHandler(HttpClient httpClient, ILogger logger)
		{
			this._httpClient = httpClient;
			this._logger = logger;
		}

		public override async Task<Boolean> InvokeAsync()
		{
			if ((String.IsNullOrEmpty(this.Options.CallbackPath) == false) && (this.Options.CallbackPath == this.Request.Path.ToString()))
			{
				return await this.InvokeReturnPathAsync();
			}

			return false;
		}

		protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
		{
			this._logger.WriteVerbose("AuthenticateCore");

			AuthenticationProperties properties = null;

			try
			{
				String code = null;
				String state = null;

				var query = this.Request.Query;
				var values = query.GetValues("code");

				if ((values != null) && (values.Count == 1))
				{
					code = values[0];
				}

				values = query.GetValues("state");

				if ((values != null) && (values.Count == 1))
				{
					state = values[0];
				}

				properties = this.Options.StateDataFormat.Unprotect(state);

				if (properties == null)
				{
					return null;
				}

				// OAuth2 10.12 CSRF
				if (this.ValidateCorrelationId(properties, this._logger) == false)
				{
					return new AuthenticationTicket(null, properties);
				}

				var tokenRequestParameters = new List<KeyValuePair<String, String>>()
				{
					new KeyValuePair<String, String>("client_id", this.Options.ClientId),
					new KeyValuePair<String, String>("client_secret", this.Options.ClientSecret),
					new KeyValuePair<String, String>("grant_type", "authorization_code"),
					new KeyValuePair<String, String>("redirect_uri", this.GenerateRedirectUri()),
					new KeyValuePair<String, String>("code", code),
				};

				var requestContent = new FormUrlEncodedContent(tokenRequestParameters);

				var response = await this._httpClient.PostAsync(TokenEndpoint, requestContent, this.Request.CallCancelled);
				response.EnsureSuccessStatusCode();

				var oauthTokenResponse = await response.Content.ReadAsStringAsync();

				var oauth2Token = JObject.Parse(oauthTokenResponse);
				var accessToken = oauth2Token["access_token"].Value<String>();

				if (String.IsNullOrWhiteSpace(accessToken) == true)
				{
					this._logger.WriteWarning("Access token was not found");
					return new AuthenticationTicket(null, properties);
				}

				var graphResponse = await this._httpClient.GetAsync(GraphApiEndpoint + "?oauth_token=" + Uri.EscapeDataString(accessToken), Request.CallCancelled);
				graphResponse.EnsureSuccessStatusCode();

				var accountString = await graphResponse.Content.ReadAsStringAsync();
				var accountInformation = JObject.Parse(accountString);
				var user = (JObject) accountInformation["response"]["user"];

				var context = new FoursquareAuthenticatedContext(this.Context, user, accessToken);

				context.Identity = new ClaimsIdentity(
					new[]
					{
						new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, this.Options.AuthenticationType),
						new Claim(ClaimTypes.Name, context.Name, XmlSchemaString, this.Options.AuthenticationType),
						new Claim("urn:foursquare:id", context.Id, XmlSchemaString, this.Options.AuthenticationType),
						new Claim("urn:foursquare:name", context.Name, XmlSchemaString, this.Options.AuthenticationType)
					},
					this.Options.AuthenticationType,
					ClaimsIdentity.DefaultNameClaimType,
					ClaimsIdentity.DefaultRoleClaimType);

				if (String.IsNullOrWhiteSpace(context.Email) == false)
				{
					context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, this.Options.AuthenticationType));
				}

				await this.Options.Provider.Authenticated(context);

				context.Properties = properties;

				return new AuthenticationTicket(context.Identity, context.Properties);
			}
			catch (Exception ex)
			{
				this._logger.WriteWarning("Authentication failed", ex);
				return new AuthenticationTicket(null, properties);
			}
		}

		protected override Task ApplyResponseChallengeAsync()
		{
			this._logger.WriteVerbose("ApplyResponseChallenge");

			if (this.Response.StatusCode != (Int32) HttpStatusCode.Unauthorized)
			{
				return Task.FromResult<Object>(null);
			}

			var challenge = Helper.LookupChallenge(this.Options.AuthenticationType, this.Options.AuthenticationMode);

			if (challenge != null)
			{
				var baseUri = this.Request.Scheme + Uri.SchemeDelimiter + this.Request.Host + this.Request.PathBase;
				var currentUri = baseUri + this.Request.Path + this.Request.QueryString;
				var redirectUri = baseUri + this.Options.CallbackPath;

				var extra = challenge.Properties;

				if (String.IsNullOrEmpty(extra.RedirectUri) == true)
				{
					extra.RedirectUri = currentUri;
				}

				// OAuth2 10.12 CSRF
				this.GenerateCorrelationId(extra);

				// OAuth2 3.3 space separated
				var scope = String.Join(" ", this.Options.Scope);

				var state = this.Options.StateDataFormat.Protect(extra);

				var authorizationEndpoint = AuthorizationEndpoint +
						"?client_id=" + Uri.EscapeDataString(this.Options.ClientId) +
						"&response_type=code" +
						"&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
						"&state=" + Uri.EscapeDataString(state);

				this.Response.StatusCode = (Int32) HttpStatusCode.Moved;
				this.Response.Headers.Set("Location", authorizationEndpoint);
			}

			return Task.FromResult<Object>(null);
		}

		public async Task<Boolean> InvokeReturnPathAsync()
		{
			this._logger.WriteVerbose("InvokeReturnPath");

			var model = await this.AuthenticateAsync();

			var context = new FoursquareReturnEndpointContext(Context, model);
			context.SignInAsAuthenticationType = this.Options.SignInAsAuthenticationType;
			context.RedirectUri = model.Properties.RedirectUri;

			model.Properties.RedirectUri = null;

			await this.Options.Provider.ReturnEndpoint(context);

			if ((context.SignInAsAuthenticationType != null) && (context.Identity != null))
			{
				var signInIdentity = context.Identity;

				if (String.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal) == false)
				{
					signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
				}

				this.Context.Authentication.SignIn(context.Properties, signInIdentity);
			}

			if ((context.IsRequestCompleted == false) && (context.RedirectUri != null))
			{
				if (context.Identity == null)
				{
					context.RedirectUri = WebUtilities.AddQueryString(context.RedirectUri, "error", "access_denied");
				}

				this.Response.Redirect(context.RedirectUri);

				context.RequestCompleted();
			}

			return context.IsRequestCompleted;
		}

		private String GenerateRedirectUri()
		{
			var requestPrefix = this.Request.Scheme + "://" + this.Request.Host;
			var redirectUri = requestPrefix + this.RequestPathBase + this.Options.CallbackPath;
			return redirectUri;
		}
	}
}