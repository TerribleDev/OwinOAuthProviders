using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Slack.Provider
{
    public class SlackAuthenticatedContextWebhook
    {
        public SlackAuthenticatedContextWebhook()
        {

        }
        public SlackAuthenticatedContextWebhook(string url, string channel, string configurationUrl)
        {
            this.url = url;
            this.channel = channel;
            this.configuration_url = configuration_url;
        }
        public string url { get; set; }
        public string channel { get; set; }
        public string configuration_url { get; set; }

    }
}
