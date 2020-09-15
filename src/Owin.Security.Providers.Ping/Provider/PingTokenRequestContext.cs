namespace Owin.Security.Providers.Ping.Provider
{

    using Microsoft.Owin;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Provider;

    /// <summary>
    ///     The ping federate authenticating context.
    /// </summary>
    public class PingTokenRequestContext : BaseContext
    {
        #region Constructors and Destructors

        /// <summary>Initializes a new instance of the <see cref="PingFederateTokenRequestContext"/> class.</summary>
        /// <param name="context">The context.</param>
        /// <param name="options">The options.</param>
        /// <param name="state">The state.</param>
        /// <param name="code">The code.</param>
        /// <param name="properties">The properties</param>
        public PingTokenRequestContext(IOwinContext context, PingAuthenticationOptions options, string state, string code, AuthenticationProperties properties)
            : base(context)
        {
            this.Context = context;
            this.Options = options;
            this.State = state;
            this.Code = code;
            this.Properties = properties;
        }

        #endregion

        #region Public Properties

        /// <summary>Gets or sets the code.</summary>
        public string Code { get; set; }

        /// <summary>
        ///     Gets or sets the context.
        /// </summary>
        public IOwinContext Context { get; set; }

        /// <summary>
        ///     Gets or sets the options.
        /// </summary>
        public PingAuthenticationOptions Options { get; set; }

        /// <summary>Gets or sets the properties.</summary>
        public AuthenticationProperties Properties { get; set; }

        /// <summary>Gets or sets the state.</summary>
        public string State { get; set; }

        #endregion
    }
}
