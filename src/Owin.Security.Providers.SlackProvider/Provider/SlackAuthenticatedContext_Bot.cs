using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Slack.Provider
{
    /// <summary>
    /// Maintains bot data when the bot scope was requested.
    /// </summary>
    public class SlackAuthenticatedContext_Bot
    {
        public SlackAuthenticatedContext_Bot(){

        }
        public SlackAuthenticatedContext_Bot(JObject botnode)
        {
            this.userId = SlackAuthenticatedContext.TryGetValue(botnode, "bot_user_id");
            this.AccessToken = SlackAuthenticatedContext.TryGetValue(botnode, "bot_access_token");
        }
        public string userId { get; set; }
        public string AccessToken { get; set; }

    }
}
