using System.Configuration;

namespace Owin.Security.Providers.Configuration
{
    /// <summary>
    /// The configuration element contains the configuration values of Facebook Identity
    /// </summary>
    public class FacebookConfigurationElement : ConfigurationElement
    {
        /// <summary>
        /// Get or set the status of availability of the identity provider
        /// </summary>
        [ConfigurationProperty("Enabled", DefaultValue = "false", IsRequired = false)]
        public bool Enabled
        {
            get { return (bool)this["Enabled"]; }
            set { this["Enabled"] = value; }
        }

        /// <summary>
        /// Get or set the identifier of customer for the identity provider
        /// </summary>
        [ConfigurationProperty("AppId", IsRequired = true)]
        public string AppId
        {
            get { return (string)this["AppId"]; }
            set { this["AppId"] = value; }
        }

        /// <summary>
        /// Get or set the secret key of customer for the identity provider
        /// </summary>
        [ConfigurationProperty("AppSecret", IsRequired = true)]
        public string AppSecret
        {
            get { return (string)this["AppSecret"]; }
            set { this["AppSecret"] = value; }
        }
    }
}