using System.Collections.Generic;

namespace Owin.Security.Providers.GooglePlus
{
    /// <summary>
    /// This was copied from Thinktecture.IdentityServer.Core.Extensions
    /// not sure how to handle this. One option is to add a reference to the namespace above
    /// another option is to copy that code to this project
    /// </summary>
    public static class FooExtensions
    {
        //https://github.com/IdentityServer/IdentityServer3/blob/e50124f4ca02175ea4011dab32a5cb7bea81bdab/source/Core/Extensions/OwinExtensions.cs
        public static string GetIdentityServerBaseUrl(this IDictionary<string, object> env)
        {
            return env.GetIdentityServerHost() + env.GetIdentityServerBasePath();
        }

        public static string GetIdentityServerHost(this IDictionary<string, object> env)
        {
            return env[OwinEnvironment.IdentityServerHost] as string;
        }

        public static string GetIdentityServerBasePath(this IDictionary<string, object> env)
        {
            return env[OwinEnvironment.IdentityServerBasePath] as string;
        }

        // https://github.com/IdentityServer/IdentityServer3/blob/db9646650cf611f25d930c176fa2889101a0447a/source/Core/Extensions/StringsExtensions.cs
        public static string RemoveTrailingSlash(this string url)
        {
            if (url != null && url.EndsWith("/"))
            {
                url = url.Substring(0, url.Length - 1);
            }
            return url;
        }
    }

    // https://github.com/IdentityServer/IdentityServer3/blob/e50124f4ca02175ea4011dab32a5cb7bea81bdab/source/Core/Constants.cs
    public static class OwinEnvironment
    {
        public const string IdentityServerBasePath = "idsrv:IdentityServerBasePath";
        public const string IdentityServerHost = "idsrv:IdentityServerHost";
        public const string AutofacScope = "idsrv:AutofacScope";
        public const string RequestId = "idsrv:RequestId";
    }
}
