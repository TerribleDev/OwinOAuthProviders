using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Net.Http;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using Microsoft.Owin;
using Owin.Security.Providers.Strava.Provider;

namespace Owin.Security.Providers.Strava
{
    public class StravaAuthenticationOptions : AuthenticationOptions
    {
        public ICertificateValidator BackchannelCertificateValidator { get; set; }
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string AuthorizationEndpoint { get; set; }
        public string TokenEndpoint { get; set; }
        public string UserInformationEndpoint { get; set; }
        public TimeSpan BackchannelTimeout { get; set; }
        public HttpMessageHandler BackchannelHttpHandler { get; set; }
        public IList<string> Scope { get; set; }
        public PathString CallbackPath { get; set; }
        public string SignInAsAuthenticationType { get; set; }
        public IStravaAuthenticationProvider Provider { get; set; }
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
        public ICookieManager CookieManager { get; set; }

        public StravaAuthenticationOptions(): base(StravaAuthenticationConstants.DefaultAuthenticationType)
        {
            Caption = StravaAuthenticationConstants.DefaultAuthenticationType;
            CallbackPath = new PathString("/sign-strava");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>();
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            CookieManager = new CookieManager();
            AuthorizationEndpoint = StravaAuthenticationConstants.AuthorizationEndpoint;
            TokenEndpoint = StravaAuthenticationConstants.TokenEndpoint;
            UserInformationEndpoint = StravaAuthenticationConstants.UserInformationEndpoint; 
            
        }
    }

}