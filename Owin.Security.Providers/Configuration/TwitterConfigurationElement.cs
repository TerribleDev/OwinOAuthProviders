using System.Configuration;

namespace Owin.Security.Providers.Configuration
{
    /// <summary>
    /// The configuration element contains the configuration values of Twitter Identity
    /// </summary>
    public class TwitterConfigurationElement : ConfigurationElement
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
        [ConfigurationProperty("ConsumerKey", IsRequired = true)]
        public string ConsumerKey
        {
            get { return (string)this["ConsumerKey"]; }
            set { this["ConsumerKey"] = value; }
        }

        /// <summary>
        /// Get or set the secret key of customer for the identity provider
        /// </summary>
        [ConfigurationProperty("ConsumerSecret", IsRequired = true)]
        public string ConsumerSecret
        {
            get { return (string)this["ConsumerSecret"]; }
            set { this["ConsumerSecret"] = value; }
        }
    }
}