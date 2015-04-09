using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Owin.Security.Providers.Wargaming
{
    internal static class Constants
    {
        internal const string DefaultAuthenticationType = "Wargaming";

        internal const string ProviderDiscoveryUriNorthAmerica = "https://na.wargaming.net/id/openid/";
        internal const string ProviderDiscoveryUriEurope = "https://eu.wargaming.net/id/openid/";
        internal const string ProviderDiscoveryUriRussia = "https://ru.wargaming.net/id/openid/";
        internal const string ProviderDiscoveryUriAsia = "https://asia.wargaming.net/id/openid/";
        internal const string ProviderDiscoveryUriKorea = "https://kr.wargaming.net/id/openid/";
    }
}