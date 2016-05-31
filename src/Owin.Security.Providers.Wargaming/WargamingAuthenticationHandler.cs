using Microsoft.Owin.Logging;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Owin.Security.Providers.OpenIDBase;

namespace Owin.Security.Providers.Wargaming
{
    internal sealed class WargamingAuthenticationHandler : OpenIDAuthenticationHandlerBase<WargamingAuthenticationOptions>
    {
        private readonly Regex _accountIDRegex = new Regex(@"^https://na.wargaming.net/id/([0-9]{10}).*$", RegexOptions.Compiled);

        private const string UserInfoUri = "https://api.worldoftanks.com/wot/account/info/?application_id={0}&account_id={1}&fields=nickname";

        public WargamingAuthenticationHandler(HttpClient httpClient, ILogger logger)
            : base(httpClient, logger)
		{
		}

        protected override void SetIdentityInformations(ClaimsIdentity identity, string claimedID, IDictionary<string, string> attributeExchangeProperties)
        {
            var accountIDMatch = _accountIDRegex.Match(claimedID);
            if (!accountIDMatch.Success) return;
            var accountID = accountIDMatch.Groups[1].Value;
            var getUserInfoTask = HTTPClient.GetStringAsync(string.Format(UserInfoUri, Options.AppId, accountID));
            getUserInfoTask.Wait();
            var userInfoRaw = getUserInfoTask.Result;
            dynamic userInfo = JsonConvert.DeserializeObject(userInfoRaw);
            identity.AddClaim(new Claim(ClaimTypes.Name, (string)userInfo["data"][accountID].nickname, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType));
        }
    }
}