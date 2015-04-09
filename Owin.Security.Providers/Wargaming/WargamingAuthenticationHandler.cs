using Microsoft.Owin.Logging;
using Newtonsoft.Json;
using Owin.Security.Providers.OpenID;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Text.RegularExpressions;

namespace Owin.Security.Providers.Wargaming
{
    internal sealed class WargamingAuthenticationHandler : OpenIDAuthenticationHandlerBase<WargamingAuthenticationOptions>
    {
        private readonly Regex AccountIDRegex = new Regex(@"^https://na.wargaming.net/id/([0-9]{10}).*$", RegexOptions.Compiled);

        private const string UserInfoUri = "https://api.worldoftanks.com/wot/account/info/?application_id={0}&account_id={1}&fields=nickname";

        public WargamingAuthenticationHandler(HttpClient httpClient, ILogger logger)
            : base(httpClient, logger)
		{
		}

        protected override void SetIdentityInformations(ClaimsIdentity identity, string claimedID, IDictionary<string, string> attributeExchangeProperties)
        {
            Match accountIDMatch = AccountIDRegex.Match(claimedID);
            if (accountIDMatch.Success)
            {
                string accountID = accountIDMatch.Groups[1].Value;
                var getUserInfoTask = _httpClient.GetStringAsync(string.Format(UserInfoUri, Options.AppId, accountID));
                getUserInfoTask.Wait();
                string userInfoRaw = getUserInfoTask.Result;
                dynamic userInfo = JsonConvert.DeserializeObject(userInfoRaw);
                identity.AddClaim(new Claim(ClaimTypes.Name, (string)userInfo["data"][accountID].nickname, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType));
            }
        }
    }
}