using System.Configuration;

namespace Owin.Security.Providers.Configuration
{
    /// <summary>
    /// The configuration element contains the configuration values of Google API (only usable for simple APIs like Google Traduction, Google Maps, ...)
    /// </summary>
    public class GoogleApiConfigurationElement : ConfigurationElement
    {
        /// <summary>
        /// Get or set the browser API key
        /// </summary>
        [ConfigurationProperty("BrowserKey", IsRequired = false)]
        public string BrowserKey
        {
            get { return (string)this["BrowserKey"]; }
            set { this["BrowserKey"] = value; }
        }

        /// <summary>
        /// Get or set the server API key
        /// </summary>
        [ConfigurationProperty("ServerKey", IsRequired = false)]
        public string ServerKey
        {
            get { return (string)this["ServerKey"]; }
            set { this["ServerKey"] = value; }
        }
    }
}