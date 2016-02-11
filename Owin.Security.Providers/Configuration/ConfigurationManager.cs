namespace Owin.Security.Providers.Configuration {
    
    ///<summary>
    ///This class allows to manage custom section simplest
    ///</summary>
    public static class ConfigurationManager {
        ///<summary>
        ///Get the <see cref="OwinConfigSection"/>
        ///</summary>
        public static OwinConfigSection OwinConfig {
            get { return System.Configuration.ConfigurationManager.GetSection(OwinConfigSection.SectionName) as OwinConfigSection; }
        }
    }    
}