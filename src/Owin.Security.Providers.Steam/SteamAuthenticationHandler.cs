using Microsoft.Owin.Logging;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Owin.Security.Providers.OpenIDBase;

namespace Owin.Security.Providers.Steam
{
    internal sealed class SteamAuthenticationHandler : OpenIDAuthenticationHandlerBase<SteamAuthenticationOptions>
    {
        private readonly Regex _accountIDRegex = new Regex(@"^http://steamcommunity\.com/openid/id/(7[0-9]{15,25})$", RegexOptions.Compiled);

        private const string UserInfoUri = "http://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key={0}&steamids={1}";

        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        public SteamAuthenticationHandler(HttpClient httpClient, ILogger logger) : base(httpClient, logger)
        { }

        protected override void SetIdentityInformations(ClaimsIdentity identity, string claimedID, IDictionary<string, string> attributeExchangeProperties)
        {
            if (!Options.QueryProfile) return;
            var accountIDMatch = _accountIDRegex.Match(claimedID);
            if (!accountIDMatch.Success) return;
            var accountID = accountIDMatch.Groups[1].Value;

            var getUserInfoTask = HTTPClient.GetStringAsync(string.Format(UserInfoUri, Options.ApplicationKey, accountID));
            getUserInfoTask.Wait();
            var userInfoRaw = getUserInfoTask.Result;
            dynamic userInfo = JsonConvert.DeserializeObject<dynamic>(userInfoRaw);
            identity.AddClaim(new Claim(ClaimTypes.Name, (string)userInfo.response.players[0].personaname, XmlSchemaString, Options.AuthenticationType));
            identity.AddClaim(new Claim("urn:steam:id", userInfo.response.players[0].steamid, XmlSchemaString, Options.AuthenticationType));
            identity.AddClaim(new Claim("urn:steam:profileurl", userInfo.response.players[0].profileurl, XmlSchemaString, Options.AuthenticationType));
            identity.AddClaim(new Claim("urn:steam:avatar", userInfo.response.players[0].avatar, XmlSchemaString, Options.AuthenticationType));
            identity.AddClaim(new Claim("urn:steam:avatarmedium", userInfo.response.players[0].avatarmedium, XmlSchemaString, Options.AuthenticationType));
            identity.AddClaim(new Claim("urn:steam:avatarfull", userInfo.response.players[0].avatarfull, XmlSchemaString, Options.AuthenticationType));
        }
    }
}
