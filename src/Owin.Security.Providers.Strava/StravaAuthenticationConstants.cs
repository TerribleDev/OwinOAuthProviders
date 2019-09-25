using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Owin.Security.Providers.Strava
{
    internal static class StravaAuthenticationConstants
    {
        internal const String DefaultAuthenticationType = "Strava";
        internal const string AuthorizationEndpoint = "https://www.strava.com/oauth/authorize";
        internal const string TokenEndpoint = "https://www.strava.com/oauth/token";
        internal const string UserInformationEndpoint = "https://www.strava.com/api/v3/athlete";
    }
}