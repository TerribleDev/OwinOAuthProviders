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

namespace Owin.Security.Providers.EveOnline
{
    public class EveOnlineAuthenticationHandler : AuthenticationHandler<EveOnlineAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private string _tokenEndpoint;
        private string _characterIdEndpoint ;
        private string _oauthAuthEndpoint ;
        private string _serverHost ;

        private const string _serverScheme = "https://";
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public EveOnlineAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override Task InitializeCoreAsync()
        {
            return Task.Run(() =>
            {
                switch (Options.Server)
                {
                    case Server.Singularity:
                        _serverHost = "sisilogin.testeveonline.com";
                        break;
                    default:
                        _serverHost = "login.eveonline.com";
                        break;
                }

                _tokenEndpoint = _serverScheme + _serverHost + "/oauth/token";
                _oauthAuthEndpoint = _serverScheme + _serverHost + "/oauth/authorize";
                _characterIdEndpoint = _serverScheme + _serverHost + "/oauth/verify";
            });
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
                if (!ValidateCorrelationId(properties, _logger))
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
                var tokenResponse = await _httpClient.PostAsync(_tokenEndpoint, new FormUrlEncodedContent(body));
                tokenResponse.EnsureSuccessStatusCode();
                var text = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the token response
                var response = JsonConvert.DeserializeObject<dynamic>(text);
                var accessToken = (string)response.access_token;
                var refreshToken = string.Empty;
                if (response.refresh_token != null)
                    refreshToken = (string)response.refresh_token;

                var expires = (string)response.expires_in;

                // Get character data 
                var graphRequest = new HttpRequestMessage()
                {
                    Method = HttpMethod.Get,
                    RequestUri = new Uri(_characterIdEndpoint)
                };

                graphRequest.Headers.Add("Authorization", "Bearer " + accessToken);
                graphRequest.Headers.Add("Host", _serverHost);
                graphRequest.Headers.UserAgent.ParseAdd("Microsoft Owin EveOnline middleware");
                var graphResponse = await _httpClient.SendAsync(graphRequest);
                graphResponse.EnsureSuccessStatusCode();
                text = await graphResponse.Content.ReadAsStringAsync();
                var characterId = JObject.Parse(text);

                var context = new EveOnlineAuthenticatedContext(Context, characterId, accessToken, refreshToken, expires)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType)
                };

                if (!string.IsNullOrEmpty(context.CharacterId))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.CharacterId, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.CharacterName))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Name, context.CharacterName, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.CharacterOwnerHash))
                {
                    context.Identity.AddClaim(new Claim("urn:eveonline:character_owner_hash", context.CharacterOwnerHash, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.AccessToken))
                {
                    context.Identity.AddClaim(new Claim("urn:eveonline:access_token", context.AccessToken, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.RefreshToken))
                {
                    context.Identity.AddClaim(new Claim("urn:eveonline:refresh_token", context.RefreshToken, XmlSchemaString, Options.AuthenticationType));
                }
                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);

            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
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
                    _oauthAuthEndpoint +
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
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new EveOnlineReturnEndpointContext(Context, ticket)
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
