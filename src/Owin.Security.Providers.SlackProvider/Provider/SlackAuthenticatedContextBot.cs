using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Slack.Provider
{
    /// <summary>
    /// Maintains bot data when the bot scope was requested.
    /// </summary>
    public class SlackAuthenticatedContextBot
    {
        public SlackAuthenticatedContextBot(){

        }
        public SlackAuthenticatedContextBot(string botUserId, string botAccessToken)
        {
            this.userId = botUserId;
            this.AccessToken = botAccessToken;
        }
        public string userId { get; set; }
        public string AccessToken { get; set; }

    }
}
