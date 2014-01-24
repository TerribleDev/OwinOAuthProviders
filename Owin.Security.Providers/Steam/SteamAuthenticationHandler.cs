using Microsoft.Owin.Logging;
using Newtonsoft.Json;
using Owin.Security.Providers.OpenID;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Text.RegularExpressions;

namespace Owin.Security.Providers.Steam
{
    internal sealed class SteamAuthenticationHandler : OpenIDAuthenticationHandlerBase<SteamAuthenticationOptions>
    {
        private readonly Regex AccountIDRegex = new Regex(@"^http://steamcommunity\.com/openid/id/(7[0-9]{15,25})$", RegexOptions.Compiled);

        private const string UserInfoUri = "http://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key={0}&steamids={1}";

        public SteamAuthenticationHandler(HttpClient httpClient, ILogger logger)
            : base(httpClient, logger)
        { }

        protected override void SetIdentityInformations(ClaimsIdentity identity, string claimedID, IDictionary<string, string> attributeExchangeProperties)
        {
            Match accountIDMatch = AccountIDRegex.Match(claimedID);
            if (accountIDMatch.Success)
            {
                string accountID = accountIDMatch.Groups[1].Value;

                var getUserInfoTask = _httpClient.GetStringAsync(string.Format(UserInfoUri, Options.ApplicationKey, accountID));
                getUserInfoTask.Wait();
                string userInfoRaw = getUserInfoTask.Result;
                dynamic userInfo = JsonConvert.DeserializeObject<dynamic>(userInfoRaw);
                identity.AddClaim(new Claim(ClaimTypes.Name, (string)userInfo.response.players[0].personaname, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType));
            }
        }
    }
}
