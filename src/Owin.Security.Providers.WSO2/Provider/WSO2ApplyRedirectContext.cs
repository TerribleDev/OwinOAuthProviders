using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.WSO2
{
	public class WSO2ApplyRedirectContext : BaseContext<WSO2AuthenticationOptions>
	{
		/// <summary>
		/// Creates a new context object.
		/// </summary>
		/// <param name="context">The Owin request context</param>
		/// <param name="options">The LinkedIn middleware options</param>
		/// <param name="properties">The authenticaiton properties of the challenge</param>
		/// <param name="redirectUri">The initial redirect URI</param>
		public WSO2ApplyRedirectContext(IOwinContext context, WSO2AuthenticationOptions options,
			AuthenticationProperties properties, string redirectUri)
            : base(context, options)
        {
			RedirectUri = redirectUri;
			Properties = properties;
		}

		/// <summary>
		/// Gets the URI used for the redirect operation.
		/// </summary>
		public string RedirectUri { get; private set; }

		/// <summary>
		/// Gets the authentication properties of the challenge
		/// </summary>
		public AuthenticationProperties Properties { get; private set; }
	}
}
