using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.LinkedIn
{
    public class LinkedInAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to LinkedIn.
        /// </summary>
        /// <value>
        ///     The pinned certificate validator.
        /// </value>
        /// <remarks>
        ///     If this property is null then the default certificate checks are performed,
        ///     validating the subject name and if the signing chain is a trusted party.
        /// </remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        ///     The HttpMessageHandler used to communicate with LinkedIn.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with LinkedIn.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-linkedin".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        ///     Gets or sets the middleware host name.
        ///     The middleware processes the <see cref="CallbackPath"/> on this host name instead of the application's request host.
        ///     If this is not set, the application's request host will be used.
        /// </summary>
        /// <remarks>
        ///     Use this property when running behind a proxy.
        /// </remarks>
        public string ProxyHost { get; set; }

        /// <summary>
        ///     Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        /// <summary>
        ///     Gets or sets the LinkedIn supplied Client ID
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     Gets or sets the LinkedIn supplied Client Secret
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        ///     Gets the list of profile fields to retrieve when signing in. 
        /// </summary>
        /// <remarks>
        ///     See https://developer.linkedin.com/docs/fields/basic-profile for the list of available Basic Profile fields. 
        ///     There are additional member profile fields available, see https://developer.linkedin.com/docs/fields/full-profile. 
        ///     Access to these fields requires that you apply for and are granted access to this information from LinkedIn.
        ///     
        ///     The following fields are added to the list by default: id, first-name, last-name, formatted-name ,email-address, public-profile-url, picture-url
        /// 
        ///     You can access the returned fields through the <see cref="LinkedInAuthenticatedContext.User"/> property.
        /// </remarks>
        public IList<string> ProfileFields { get; private set; }

        /// <summary>
        ///     Gets or sets the <see cref="ILinkedInAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public ILinkedInAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// A list of permissions to request.
        /// </summary>
        public IList<string> Scope { get; private set; }

        /// <summary>
        ///     Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user
        ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        ///     Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        ///     Initializes a new <see cref="LinkedInAuthenticationOptions" />
        /// </summary>
        public LinkedInAuthenticationOptions()
            : base("LinkedIn")
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-linkedin");
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>
            {
                "r_basicprofile",
                "r_emailaddress"
            };
            ProfileFields = new List<string>
            {
                "id",
                "first-name",
                "last-name",
                "formatted-name",
                "email-address",
                "public-profile-url",
                "picture-url",
                "industry",
                "headline",
                "summary",
                "positions"
            };
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }
    }
}