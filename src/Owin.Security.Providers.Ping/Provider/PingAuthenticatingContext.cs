namespace Owin.Security.Providers.Ping.Provider
{
    using System.Security.Claims;
    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;
    using Newtonsoft.Json.Linq;
    public class PingAuthenticatingContext : BaseContext
    {
        #region Constructors and Destructors

        /// <summary>Initializes a new instance of the <see cref="PingAuthenticatingContext"/> class.</summary>
        /// <param name="context">The context.</param>
        /// <param name="options">The options.</param>
        public PingAuthenticatingContext(IOwinContext context, PingAuthenticationOptions options)
            : base(context)
        {
            this.Context = context;
            this.Options = options;
        }

        #endregion

        #region Public Properties

        /// <summary>
        ///     Gets or sets the context.
        /// </summary>
        public IOwinContext Context { get; set; }

        /// <summary>
        ///     Gets or sets the options.
        /// </summary>
        public PingAuthenticationOptions Options { get; set; }

        #endregion
    }
}
