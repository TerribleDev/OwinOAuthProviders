using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Configuration
{
    /// <summary>
    /// The configuration element contains the configuration values of Email Two-Factor Authentication Identity
    /// </summary>
    public class EmailTwoFactorAuthenticationConfigurationElement : ConfigurationElement
    {
        /// <summary>
        /// Get or set the status of availability of the Email provider
        /// </summary>
        [ConfigurationProperty("Enabled", DefaultValue = "false", IsRequired = false)]
        public bool Enabled
        {
            get { return (bool)this["Enabled"]; }
            set { this["Enabled"] = value; }
        }

        /// <summary>
        /// Get or set the sender of the email
        /// </summary>
        [ConfigurationProperty("From", IsRequired = true)]
        public string From
        {
            get { return (string)this["From"]; }
            set { this["From"] = value; }
        }

        /// <summary>
        /// Get or set the friendly display name of the sender of the email
        /// </summary>
        [ConfigurationProperty("FromDisplayName", IsRequired = true)]
        public string FromDisplayName
        {
            get { return (string)this["FromDisplayName"]; }
            set { this["FromDisplayName"] = value; }
        }

        /// <summary>
        /// Get or set the copy email(s)
        /// </summary>
        [ConfigurationProperty("Copies", IsRequired = false)]
        public string Copies
        {
            get { return (string)this["Copies"]; }
            set { this["Copies"] = value; }
        }
    }
}
