using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Strava.Provider
{
    public class StravaAuthenticatedContext : BaseContext 
    {
        private IOwinContext context;
        public JObject User { get; private set; }
        public string AccessToken { get; private set; }
        public string RefreshToken { get; private set; }
        public TimeSpan? ExpiresIn { get; set; }
        public string Id { get; private set; }
        public string UserName { get; private set; }
        public string FirstName { get; private set; }
        public string LastName { get; private set; }       
        public string City { get; private set; }
        public string State { get; private set; }
        public string Country { get; private set; }
        public string ProfileMediumPictureLink { get; private set; }
        public string ProfileLargePictureLink { get; private set; }
        public ClaimsIdentity Identity { get; set; }
        public AuthenticationProperties Properties { get; set; }

        public StravaAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string refreshToken, string expires) : base(context)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            IDictionary<string, JToken> userAsDictionary = user;

            User = user;
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }
         
            
            Id = GetValueOrDefault("username", userAsDictionary);
            UserName = GetValueOrDefault("username", userAsDictionary);
            FirstName = GetValueOrDefault("firstname", userAsDictionary);
            LastName = GetValueOrDefault("lastname", userAsDictionary);            
            City = GetValueOrDefault("city", userAsDictionary);
            State = GetValueOrDefault("state", userAsDictionary);
            Country = GetValueOrDefault("country", userAsDictionary);
            ProfileMediumPictureLink = GetValueOrDefault("profile_medium", userAsDictionary);
            ProfileLargePictureLink = GetValueOrDefault("profile", userAsDictionary);           
        }

        private static string GetValueOrDefault(string property, IDictionary<string, JToken> dictionary, string defaultValue=null)
        {
            JToken value;
            dictionary.TryGetValue(property, out value);
            return value.ToString();
        }

    }
}