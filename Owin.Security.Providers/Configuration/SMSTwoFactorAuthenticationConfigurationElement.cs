using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Configuration
{
    /// <summary>
    /// The configuration element contains the configuration values of SMS Two-Factor Authentication Identity
    /// </summary>
    public class SmsTwoFactorAuthenticationConfigurationElement : ConfigurationElement
    {
        /// <summary>
        /// Get or set the status of availability of the SMS provider
        /// </summary>
        [ConfigurationProperty("Enabled", DefaultValue = "false", IsRequired = false)]
        public bool Enabled
        {
            get { return (bool)this["Enabled"]; }
            set { this["Enabled"] = value; }
        }
        
        /// <summary>
        /// Get or set the account identifier for the SMS provider
        /// </summary>
        [ConfigurationProperty("AccountSid", IsRequired = true)]
        public string AccountSid
        {
            get { return (string)this["AccountSid"]; }
            set { this["AccountSid"] = value; }
        }

        /// <summary>
        /// Get or set the authentication token for the SMS provider
        /// </summary>
        [ConfigurationProperty("AuthToken", IsRequired = true)]
        public string AuthToken
        {
            get { return (string)this["AuthToken"]; }
            set { this["AuthToken"] = value; }
        }

        /// <summary>
        /// Get or set the phone number of account for the SMS provider
        /// </summary>
        [ConfigurationProperty("PhoneNumber", IsRequired = true)]
        public string PhoneNumber
        {
            get { return (string)this["PhoneNumber"]; }
            set { this["PhoneNumber"] = value; }
        }
    }
}
