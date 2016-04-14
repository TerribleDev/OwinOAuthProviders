using Microsoft.Owin.Security.DataHandler.Serializer;

namespace Owin.Security.Providers.Xing.Messages
{
    /// <summary>
    /// Provides access to a request token serializer
    /// </summary>
    public static class Serializers
    {
        static Serializers()
        {
            RequestToken = new RequestTokenSerializer();
        }

        /// <summary>
        /// Gets or sets a statically-available serializer object. The value for this property will be <see cref="RequestTokenSerializer"/> by default.
        /// </summary>
        public static IDataSerializer<RequestToken> RequestToken { get; set; }
    }
}
