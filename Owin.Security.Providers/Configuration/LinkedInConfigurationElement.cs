using System.Configuration;

namespace Owin.Security.Providers.Configuration
{
    /// <summary>
    /// The configuration element contains the configuration values of LinkedIn Identity
    /// </summary>
    public class LinkedInConfigurationElement : ConfigurationElement
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
        [ConfigurationProperty("ClientId", IsRequired = true)]
        public string ClientId
        {
            get { return (string)this["ClientId"]; }
            set { this["ClientId"] = value; }
        }

        /// <summary>
        /// Get or set the secret key of customer for the identity provider
        /// </summary>
        [ConfigurationProperty("ClientSecret", IsRequired = true)]
        public string ClientSecret
        {
            get { return (string)this["ClientSecret"]; }
            set { this["ClientSecret"] = value; }
        }
    }
}