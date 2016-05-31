using System;
using Newtonsoft.Json;

namespace Owin.Security.Providers.DoYouBuzz.Messages
{
    [Serializable]
    internal class UserInfo
    {
        /// <summary>
        /// The unique identifier
        /// </summary>
        [JsonProperty("id")]
        public int Id { get; set; }
        
        /// <summary>
        /// The last name
        /// </summary>
        [JsonProperty("lastname")]
        public string LastName { get; set; } 

        /// <summary>
        /// The first name
        /// </summary>
        [JsonProperty("firstname")]
        public string FirstName { get; set; }

        /// <summary>
        /// The slug of the user's profile (append to http://www.doyoubuzz.com/ to get the user's main resume url)
        /// </summary>
        [JsonProperty("slug")]
        public string Slug { get; set; }

        /// <summary>
        /// The registration date
        /// </summary>
        [JsonProperty("registeredAt")]
        public DateTime RegisteredAt { get; set; }

        /// <summary>
        /// Indicates if the user is a Premium DoYouBuzz user
        /// </summary>
        [JsonProperty("premium")]
        public bool Premium { get; set; }

        /// <summary>
        /// The email verified
        /// </summary>
        [JsonProperty("email")]
        public string Email { get; set; }

        /// <summary>
        /// The user's resumes
        /// </summary>
        [JsonProperty("resumes")]
        public Resume[] Resumes { get; set; }
    }
}
