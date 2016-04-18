namespace Owin.Security.Providers.DoYouBuzz.Messages
{
    /// <summary>
    /// DoYouBuzz access token
    /// </summary>
    public class AccessToken : RequestToken
    {
        /// <summary>
        /// Gets or sets the DoYouBuzz User ID
        /// </summary>
        public string UserId { get; set; }
    }
}