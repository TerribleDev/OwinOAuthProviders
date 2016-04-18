namespace Owin.Security.Providers.Xing.Messages
{
    /// <summary>
    /// Xing access token
    /// </summary>
    public class AccessToken : RequestToken
    {
        /// <summary>
        /// Gets or sets the Xing User ID
        /// </summary>
        public string UserId { get; set; }
    }
}