using Owin.Security.Providers.OpenIDBase;

namespace Owin.Security.Providers.Wargaming
{
    public class WargamingAuthenticationOptions : OpenIDAuthenticationOptions
    {
        /// <summary>
        /// Region to use for to log in
        /// </summary>
        public enum Region
        {
            NorthAmerica,
            Europe,
            Russia,
            Asia,
            Korea
        }

        /// <summary>
        /// Gets or sets the Wargaming-assigned appId
        /// </summary>
        public string AppId { get; set; }
    }
}
