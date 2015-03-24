using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Owin.Security.Providers.HealthGraph.Provider;

namespace Owin.Security.Providers.HealthGraph
{
    public class HealthGraphAuthenticationOptions : AuthenticationOptions
    {
        private const string AuthorizationEndPoint = "https://runkeeper.com/apps/authorize";
        private const string TokenEndpoint = "https://runkeeper.com/apps/token";
        private const string UserInfoEndpoint = "https://api.runkeeper.com/user";
        private const string ProfileInfoEndpoint = "https://api.runkeeper.com/profile";
        
        public class HealthGraphAuthenticationEndpoints
        {
            /// <summary>
            /// Endpoint which is used to redirect users to request GitHub access
            /// </summary>
            /// <remarks>
            /// Defaults to https://runkeeper.com/apps/authorize
            /// </remarks>
            public string AuthorizationEndpoint { get; set; }

            /// <summary>
            /// Endpoint which is used to exchange code for access token
            /// </summary>
            /// <remarks>
            /// Defaults to https://api.runkeeper.com/profile
            /// </remarks>
            public string TokenEndpoint { get; set; }

            /// <summary>
            /// Endpoint which is used to obtain user information after authentication
            /// </summary>
            /// <remarks>
            /// Defaults to https://api.runkeeper.com/user
            /// </remarks>
            public string UserInfoEndpoint { get; set; }


            /// <summary>
            /// Endpoint which is used to obtain user information after authentication
            /// </summary>
            /// <remarks>
            /// Defaults to https://api.runkeeper.com/profile
            /// </remarks>
            public string ProfileInfoEndpoint { get; set; }
        }

        public HealthGraphAuthenticationOptions() 
            : base(Constants.DefaultAuthenticationType)
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-healthgraph");
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            Endpoints = new HealthGraphAuthenticationEndpoints
            {
                AuthorizationEndpoint = AuthorizationEndPoint,
                TokenEndpoint = TokenEndpoint,
                UserInfoEndpoint = UserInfoEndpoint,
                ProfileInfoEndpoint = ProfileInfoEndpoint,
            };
        }

        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        public TimeSpan BackchannelTimeout { get; set; }

        public PathString CallbackPath { get; set; }

        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }
        
        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public PropertiesDataFormat StateDataFormat { get; set; }

        public HealthGraphAuthenticationEndpoints Endpoints { get; set; }

        public IHealthGraphAuthenticationProvider Provider { get; set; }

        public string SignInAsAuthenticationType { get; set; }
    }
}
