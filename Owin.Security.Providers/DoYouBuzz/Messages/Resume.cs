using System;
using Newtonsoft.Json;

namespace Owin.Security.Providers.DoYouBuzz.Messages
{
    [Serializable]
    [JsonArray("resume")]
    internal class Resume
    {
        /// <summary>
        /// The unique identifier
        /// </summary>
        [JsonProperty("id")]
        public int Id { get; set; }

        /// <summary>
        /// The title
        /// </summary>
        [JsonProperty("title")]
        public string Title { get; set; }

        /// <summary>
        /// Indicates if this is the user's main resume
        /// </summary>
        [JsonProperty("main")]
        public bool Main { get; set; }

        /// <summary>
        /// <para>The culture of the resume</para>
        /// <para>
        /// The possible values are
        /// <list type="disc">
        ///     <item>fr_FR</item>
        ///     <item>en_US</item>
        ///     <item>en_UK</item>
        ///     <item>it_IT</item>
        ///     <item>es_ES</item>
        ///     <item>de_DE</item>
        /// </list>
        /// </para>
        /// </summary>
        [JsonProperty("culture")]
        public string Culture { get; set; }
    }
}
