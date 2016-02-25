using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.Orcid
{
    public class OrcidAuthenticationEndpoints
    {
        public static class Default
        {
            public const string AuthorizationEndPoint = @"http://orcid.org/oauth/authorize";
            public const string TokenEndpoint = @"https://pub.orcid.org/oauth/token";
            public const string UserInfoEndpoint = @"http://pub.orcid.org/v1.2";
        }

        /// <summary>
        /// Endpoint which is used to redirect users to request Orcid access
        /// </summary>
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Endpoint which is used to exchange code for access token
        /// </summary>
        public string TokenEndpoint { get; set; }

        /// <summary>
        /// Endpoint which is used to exchange code for access token
        /// </summary>
        public string UserProfileEndpoint { get; set; }
    }
}