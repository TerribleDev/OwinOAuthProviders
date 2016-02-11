using System.Configuration;

namespace Owin.Security.Providers.Configuration
{
    /// <summary>
    /// The configuration section class determines the OWIN configuration elements
    /// </summary>
    public class OwinConfigSection : ConfigurationSection
    {
        /// <summary>
        /// The string name of the section in the configuration file as defined in its XML schema
        /// </summary>
        public const string SectionName = "owinConfig";

        /// <summary>
        /// The XML namespace
        /// </summary>
        /// <remarks>Used to solve live compilation issue</remarks>
        [ConfigurationProperty("xmlns", IsRequired = false)]
        public string XmlNamespace
        {
            get { return this["xmlns"] as string; }
            set { this["xmlns"] = value; }
        }

        /// <summary>
        /// The Google identity configuration for Identity Authentication
        /// </summary>
        [ConfigurationProperty("GoogleAuthentication", IsRequired = false)]
        public GoogleConfigurationElement GoogleAuthentication
        {
            get { return this["GoogleAuthentication"] as GoogleConfigurationElement; }
        }

        /// <summary>
        /// The Facebook identity configuration for Identity Authentication
        /// </summary>
        [ConfigurationProperty("FacebookAuthentication", IsRequired = false)]
        public FacebookConfigurationElement FacebookAuthentication
        {
            get { return this["FacebookAuthentication"] as FacebookConfigurationElement; }
        }

        /// <summary>
        /// The Twitter identity configuration for Identity Authentication
        /// </summary>
        [ConfigurationProperty("TwitterAuthentication", IsRequired = false)]
        public TwitterConfigurationElement TwitterAuthentication
        {
            get { return this["TwitterAuthentication"] as TwitterConfigurationElement; }
        }

        /// <summary>
        /// The Microsoft identity configuration for Identity Authentication
        /// </summary>
        [ConfigurationProperty("MicrosoftAuthentication", IsRequired = false)]
        public MicrosoftConfigurationElement MicrosoftAuthentication
        {
            get { return this["MicrosoftAuthentication"] as MicrosoftConfigurationElement; }
        }

        /// <summary>
        /// The LinkedIn identity configuration for Identity Authentication
        /// </summary>
        [ConfigurationProperty("LinkedInAuthentication", IsRequired = false)]
        public LinkedInConfigurationElement LinkedInAuthentication
        {
            get { return this["LinkedInAuthentication"] as LinkedInConfigurationElement; }
        }

        /// <summary>
        /// The Yammer identity configuration for Identity Authentication
        /// </summary>
        [ConfigurationProperty("YammerAuthentication", IsRequired = false)]
        public YammerConfigurationElement YammerAuthentication
        {
            get { return this["YammerAuthentication"] as YammerConfigurationElement; }
        }

        /// <summary>
        /// The Xing identity configuration for Identity Authentication
        /// </summary>
        [ConfigurationProperty("XingAuthentication", IsRequired = false)]
        public XingConfigurationElement XingAuthentication
        {
            get { return this["XingAuthentication"] as XingConfigurationElement; }
        }

        /// <summary>
        /// The DoYouBuzz identity configuration for Identity Authentication
        /// </summary>
        [ConfigurationProperty("DoYouBuzzAuthentication", IsRequired = false)]
        public DoYouBuzzConfigurationElement DoYouBuzzAuthentication
        {
            get { return this["DoYouBuzzAuthentication"] as DoYouBuzzConfigurationElement; }
        }

        /// <summary>
        /// The SMS Two-Factor Authentication identity configuration
        /// </summary>
        [ConfigurationProperty("SMSTwoFactorAuthentication", IsRequired = false)]
        public SmsTwoFactorAuthenticationConfigurationElement SMSTwoFactorAuthentication
        {
            get { return this["SMSTwoFactorAuthentication"] as SmsTwoFactorAuthenticationConfigurationElement; }
        }

        /// <summary>
        /// The Email Two-Factor Authentication identity configuration
        /// </summary>
        [ConfigurationProperty("EmailTwoFactorAuthentication", IsRequired = false)]
        public EmailTwoFactorAuthenticationConfigurationElement EmailTwoFactorAuthentication
        {
            get { return this["EmailTwoFactorAuthentication"] as EmailTwoFactorAuthenticationConfigurationElement; }
        }
    }
}
