using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.OpenIDBase.Infrastructure;

namespace Owin.Security.Providers.OpenIDBase
{
    public abstract class OpenIDAuthenticationHandlerBase<T> : AuthenticationHandler<T> where T : OpenIDAuthenticationOptions
    {
        private const string ContenttypeXrds = "application/xrds+xml";
        private const string ContenttypeHTML = "text/html";
        private const string ContenttypeXhtml = "application/xhtml+xml";
        private const string ContenttypeXml = "text/xml";
        private const string XrdsLocationheader = "X-XRDS-Location";
        private const string XrdNamespace = "xri://$xrd*($v*2.0)";

        protected readonly ILogger Logger;
        protected readonly HttpClient HTTPClient;

        protected OpenIDAuthenticationHandlerBase(HttpClient httpClient, ILogger logger)
        {
            HTTPClient = httpClient;
            Logger = logger;
        }

        public override async Task<bool> InvokeAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                return await InvokeReturnPathAsync();
            }
            return false;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                var query = Request.Query;

                properties = UnpackStateParameter(query);
                if (properties == null)
                {
                    Logger.WriteWarning("Invalid return state");
                    return null;
                }

                // Anti-CSRF
                if (!ValidateCorrelationId(properties, Logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                var message = await ParseRequestMessageAsync(query);

                var messageValidated = false;

                Property mode;
                if (!message.Properties.TryGetValue("mode.http://specs.openid.net/auth/2.0", out mode))
                {
                    Logger.WriteWarning("Missing mode parameter");
                    return new AuthenticationTicket(null, properties);
                }

                if (string.Equals("cancel", mode.Value, StringComparison.Ordinal))
                {
                    Logger.WriteWarning("User cancelled signin request");
                    return new AuthenticationTicket(null, properties);
                }

                if (string.Equals("id_res", mode.Value, StringComparison.Ordinal))
                {
                    mode.Value = "check_authentication";

                    var requestBody = new FormUrlEncodedContent(message.ToFormValues());

                    var response = await HTTPClient.PostAsync(Options.ProviderLoginUri, requestBody, Request.CallCancelled);
                    response.EnsureSuccessStatusCode();
                    var responseBody = await response.Content.ReadAsStringAsync();

                    var verifyBody = new Dictionary<string, string[]>();
                    foreach (var line in responseBody.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        var delimiter = line.IndexOf(':');
                        if (delimiter != -1)
                        {
                            verifyBody.Add("openid." + line.Substring(0, delimiter), new[] { line.Substring(delimiter + 1) });
                        }
                    }
                    var verifyMessage = new Message(new ReadableStringCollection(verifyBody), false);
                    Property isValid;
                    if (verifyMessage.Properties.TryGetValue("is_valid.http://specs.openid.net/auth/2.0", out isValid))
                    {
                        messageValidated = string.Equals("true", isValid.Value, StringComparison.Ordinal);
                    }
                }

                // http://openid.net/specs/openid-authentication-2_0.html#verify_return_to
                // To verify that the "openid.return_to" URL matches the URL that is processing this assertion:
                // * The URL scheme, authority, and path MUST be the same between the two URLs.
                // * Any query parameters that are present in the "openid.return_to" URL MUST also
                //   be present with the same values in the URL of the HTTP request the RP received.
                if (messageValidated)
                {
                    // locate the required return_to parameter
                    string actualReturnTo;
                    if (!message.TryGetValue("return_to.http://specs.openid.net/auth/2.0", out actualReturnTo))
                    {
                        Logger.WriteWarning("openid.return_to parameter missing at return address");
                        messageValidated = false;
                    }
                    else
                    {
                        // create the expected return_to parameter based on the URL that is processing 
                        // the assertion, plus exactly and only the the query string parameter (state)
                        // that this RP must have received
                        var expectedReturnTo = BuildReturnTo(GetStateParameter(query));

                        if (!string.Equals(actualReturnTo, expectedReturnTo, StringComparison.Ordinal))
                        {
                            Logger.WriteWarning("openid.return_to parameter not equal to expected value based on return address");
                            messageValidated = false;
                        }
                    }
                }

                // Allow protocol extensions to add custom message validation rules
                foreach (var protocolExtension in Options.ProtocolExtensions)
                {
                    if (!await protocolExtension.OnValidateMessageAsync(message))
                    {
                        messageValidated = false;
                    }
                }

                if (!messageValidated) return new AuthenticationTicket(null, properties);
                {
                    IDictionary<string, string> attributeExchangeProperties = new Dictionary<string, string>();
                    foreach (var typeProperty in message.Properties.Values)
                    {
                        if (typeProperty.Namespace != "http://openid.net/srv/ax/1.0" || !typeProperty.Name.StartsWith("type.")) continue;
                        var name = "value." + typeProperty.Name.Substring("type.".Length) + "http://openid.net/srv/ax/1.0";
                        Property valueProperty;
                        if (message.Properties.TryGetValue(name, out valueProperty))
                        {
                            attributeExchangeProperties.Add(typeProperty.Value, valueProperty.Value);
                        }
                    }

                    var responseNamespaces = new object[]
                    {
                        new XAttribute(XNamespace.Xmlns + "openid", "http://specs.openid.net/auth/2.0"),
                        new XAttribute(XNamespace.Xmlns + "openid.ax", "http://openid.net/srv/ax/1.0")
                    };

                    var responseProperties = message.Properties
                        .Where(p => p.Value.Namespace != null)
                        .Select(p => (object)new XElement(XName.Get(p.Value.Name.Substring(0, p.Value.Name.Length - 1), p.Value.Namespace), p.Value.Value));

                    var responseMessage = new XElement("response", responseNamespaces.Concat(responseProperties).ToArray());

                    var identity = new ClaimsIdentity(Options.AuthenticationType);
                    var claimedId = responseMessage.Element(XName.Get("claimed_id", "http://specs.openid.net/auth/2.0"));
                    if (claimedId != null)
                    {
                        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, claimedId.Value, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType));
                    }

                    SetIdentityInformations(identity, claimedId.Value, attributeExchangeProperties);
                    
                    var context = new OpenIDAuthenticatedContext(
                        Context,
                        identity,
                        properties,
                        responseMessage,
                        attributeExchangeProperties);


                    // Let protocol extensions to extract the results from the message
                    foreach (var protocolExtension in Options.ProtocolExtensions)
                    {
                        var result = await protocolExtension.OnExtractResultsAsync(identity, claimedId.Value, message);
                        context.ProtocolExtensionData[protocolExtension.GetType()] = result;
                    }

                    await Options.Provider.Authenticated(context);

                    return new AuthenticationTicket(context.Identity, context.Properties);
                }
            }
            catch (Exception ex)
            {
                Logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }

        protected virtual void SetIdentityInformations(ClaimsIdentity identity, string claimedID, IDictionary<string, string> attributeExchangeProperties)
        {
            string emailValue;
            if (attributeExchangeProperties.TryGetValue("http://axschema.org/contact/email", out emailValue))
            {
                identity.AddClaim(new Claim(ClaimTypes.Email, emailValue, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType));
            }

            string firstValue;
            if (attributeExchangeProperties.TryGetValue("http://axschema.org/namePerson/first", out firstValue))
            {
                identity.AddClaim(new Claim(ClaimTypes.GivenName, firstValue, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType));
            }

            string lastValue;
            if (attributeExchangeProperties.TryGetValue("http://axschema.org/namePerson/last", out lastValue))
            {
                identity.AddClaim(new Claim(ClaimTypes.Surname, lastValue, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType));
            }

            string nameValue;
            if (!attributeExchangeProperties.TryGetValue("http://axschema.org/namePerson", out nameValue))
            {
                if (!string.IsNullOrEmpty(firstValue) && !string.IsNullOrEmpty(lastValue))
                {
                    nameValue = firstValue + " " + lastValue;
                }
                else if (!string.IsNullOrEmpty(firstValue))
                {
                    nameValue = firstValue;
                }
                else if (!string.IsNullOrEmpty(lastValue))
                {
                    nameValue = lastValue;
                }
                else if (!string.IsNullOrEmpty(emailValue) && emailValue.Contains("@"))
                {
                    nameValue = emailValue.Substring(0, emailValue.IndexOf('@'));
                }
                else
                {
                    nameValue = claimedID;
                }
            }

            identity.AddClaim(new Claim(ClaimTypes.Name, nameValue, "http://www.w3.org/2001/XMLSchema#string", Options.AuthenticationType));

        }

        private static string GetStateParameter(IReadableStringCollection query)
        {
            var values = query.GetValues("state");
            if (values != null && values.Count == 1)
            {
                return values[0];
            }
            return null;
        }

        private AuthenticationProperties UnpackStateParameter(IReadableStringCollection query)
        {
            var state = GetStateParameter(query);
            if (state != null)
            {
                return Options.StateDataFormat.Unprotect(state);
            }
            return null;
        }

        private string BuildReturnTo(string state)
        {
            return Request.Scheme + "://" + Request.Host +
                   RequestPathBase + Options.CallbackPath +
                   "?state=" + Uri.EscapeDataString(state);
        }

        private async Task<Message> ParseRequestMessageAsync(IReadableStringCollection query)
        {
            if (Request.Method != "POST") return new Message(query, true);
            var form = await Request.ReadFormAsync();
            return new Message(form, true);
        }

        protected override async Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return;
            }

            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                if (string.IsNullOrEmpty(Options.ProviderLoginUri))
                {
                    await DoYadisDiscoveryAsync();
                }

                if (!string.IsNullOrEmpty(Options.ProviderLoginUri))
                {
                    var requestPrefix = Request.Scheme + Uri.SchemeDelimiter + Request.Host;

                    var state = challenge.Properties;
                    if (string.IsNullOrEmpty(state.RedirectUri))
                    {
                        state.RedirectUri = requestPrefix + Request.PathBase + Request.Path + Request.QueryString;
                    }

                    // Anti-CSRF
                    GenerateCorrelationId(state);

                    var returnTo = BuildReturnTo(Options.StateDataFormat.Protect(state));

                    var authorizationEndpoint =
                        Options.ProviderLoginUri +
                        "?openid.ns=" + Uri.EscapeDataString("http://specs.openid.net/auth/2.0") +
                        "&openid.mode=" + Uri.EscapeDataString("checkid_setup") +
                        "&openid.claimed_id=" + Uri.EscapeDataString("http://specs.openid.net/auth/2.0/identifier_select") +
                        "&openid.identity=" + Uri.EscapeDataString("http://specs.openid.net/auth/2.0/identifier_select") +
                        "&openid.return_to=" + Uri.EscapeDataString(returnTo) +
                        "&openid.realm=" + Uri.EscapeDataString(requestPrefix) +

                        "&openid.ns.ax=" + Uri.EscapeDataString("http://openid.net/srv/ax/1.0") +
                        "&openid.ax.mode=" + Uri.EscapeDataString("fetch_request") +

                        "&openid.ax.type.email=" + Uri.EscapeDataString("http://axschema.org/contact/email") +
                        "&openid.ax.type.name=" + Uri.EscapeDataString("http://axschema.org/namePerson") +
                        "&openid.ax.type.first=" + Uri.EscapeDataString("http://axschema.org/namePerson/first") +
                        "&openid.ax.type.last=" + Uri.EscapeDataString("http://axschema.org/namePerson/last") +

                        "&openid.ax.type.email2=" + Uri.EscapeDataString("http://schema.openid.net/contact/email") +
                        "&openid.ax.type.name2=" + Uri.EscapeDataString("http://schema.openid.net/namePerson") +
                        "&openid.ax.type.first2=" + Uri.EscapeDataString("http://schema.openid.net/namePerson/first") +
                        "&openid.ax.type.last2=" + Uri.EscapeDataString("http://schema.openid.net/namePerson/last") +

                        "&openid.ax.required=" + Uri.EscapeDataString("email,name,first,last,email2,name2,first2,last2");

                    // allow protocol extensions to add their own attributes to the endpoint URL
                    var endpoint = new OpenIDAuthorizationEndpointInfo()
                    {
                        Url = authorizationEndpoint
                    };
                    foreach (var protocolExtension in Options.ProtocolExtensions)
                    {
                        await protocolExtension.OnChallengeAsync(challenge, endpoint);
                    }

                    Response.StatusCode = 302;
                    Response.Headers.Set("Location", endpoint.Url);
                }
            }
        }

        private async Task DoYadisDiscoveryAsync()
        {
            // 1° request
            var httpResponse = await SendRequestAsync(Options.ProviderDiscoveryUri, ContenttypeXrds, ContenttypeHTML, ContenttypeXhtml);
            if (httpResponse.StatusCode != HttpStatusCode.OK)
            {
                Logger.WriteError(
                    $"HTTP error {(int) httpResponse.StatusCode} ({httpResponse.StatusCode}) while performing discovery on {Options.ProviderDiscoveryUri}.");
                return;
            }

            await httpResponse.Content.LoadIntoBufferAsync();

            // 2° request (if necessary)
            if (!await IsXrdsDocumentAsync(httpResponse))
            {
                IEnumerable<string> uriStrings;
                string uriString = null;
                if (httpResponse.Headers.TryGetValues(XrdsLocationheader, out uriStrings))
                {
                    uriString = uriStrings.FirstOrDefault();
                }

                Uri url = null;
                if (uriString != null)
                {
                    Uri.TryCreate(uriString, UriKind.Absolute, out url);
                }

                var contentType = httpResponse.Content.Headers.ContentType;
                if (url == null && contentType != null && (contentType.MediaType == ContenttypeHTML || contentType.MediaType == ContenttypeXhtml))
                {
                    url = FindYadisDocumentLocationInHtmlMetaTags(await httpResponse.Content.ReadAsStringAsync());
                }
                if (url == null)
                {
                    Logger.WriteError($"The uri {Options.ProviderDiscoveryUri} doesn't return an XRDS document.");
                    return;
                }
                else
                {
                    httpResponse = await SendRequestAsync(url.AbsoluteUri, ContenttypeXrds);
                    if (httpResponse.StatusCode != HttpStatusCode.OK)
                    {
                        Logger.WriteError(
                            $"HTTP error {(int) httpResponse.StatusCode} {httpResponse.StatusCode} while performing discovery on {url.AbsoluteUri}.");
                        return;
                    }
                    if (!await IsXrdsDocumentAsync(httpResponse))
                    {
                        Logger.WriteError($"The uri {url.AbsoluteUri} doesn't return an XRDS document.");
                        return;
                    }
                }
            }

            // Get provider url from XRDS document
            var xrdsDoc = XDocument.Parse(await httpResponse.Content.ReadAsStringAsync());
            Options.ProviderLoginUri = xrdsDoc.Root.Element(XName.Get("XRD", "xri://$xrd*($v*2.0)"))
                .Descendants(XName.Get("Service", "xri://$xrd*($v*2.0)"))
                .Where(service => service.Descendants(XName.Get("Type", "xri://$xrd*($v*2.0)")).Any(type => type.Value == "http://specs.openid.net/auth/2.0/server"))
                .OrderBy(service =>
                {
                    var priorityAttribute = service.Attribute("priority");
                    return priorityAttribute?.Value;
                })
                .Select(service => service.Element(XName.Get("URI", "xri://$xrd*($v*2.0)")).Value)
                .FirstOrDefault();
        }

        private static Uri FindYadisDocumentLocationInHtmlMetaTags(string html)
        {
            var match = new Regex(@"<meta http-equiv=""X-XRDS-Location"" content=""(.*?)"">", RegexOptions.Compiled).Match(html);
            if (!match.Success) return null;
            Uri uri;
            return Uri.TryCreate(match.Groups[1].Value, UriKind.Absolute, out uri) ? uri : null;
        }

        private async Task<HttpResponseMessage> SendRequestAsync(string uri, params string[] acceptTypes)
        {
            var httprequest = new HttpRequestMessage(HttpMethod.Get, uri);
            if (acceptTypes == null) return await HTTPClient.SendAsync(httprequest);
            foreach (var acceptType in acceptTypes)
            {
                httprequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(acceptType));
            }

            return await HTTPClient.SendAsync(httprequest);
        }

        private static async Task<bool> IsXrdsDocumentAsync(HttpResponseMessage response)
        {
            if (response.Content.Headers.ContentType == null)
            {
                return false;
            }

            if (response.Content.Headers.ContentType.MediaType == ContenttypeXrds)
            {
                return true;
            }

            if (response.Content.Headers.ContentType.MediaType != ContenttypeXml) return false;
            using (var responseStream = await response.Content.ReadAsStreamAsync())
            {
                var reader = XmlReader.Create(responseStream, new XmlReaderSettings { MaxCharactersFromEntities = 1024, XmlResolver = null, DtdProcessing = DtdProcessing.Prohibit });

                while (await reader.ReadAsync() && reader.NodeType != XmlNodeType.Element)
                { }
                if (reader.NamespaceURI == XrdNamespace && reader.Name == "XRDS")
                {
                    return true;
                }
            }

            return false;
        }

        public async Task<bool> InvokeReturnPathAsync()
        {
            var model = await AuthenticateAsync();
            if (model == null)
            {
                Logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new OpenIDReturnEndpointContext(Context, model)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = model.Properties.RedirectUri
            };
            model.Properties.RedirectUri = null;

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null && context.Identity != null)
            {
                var signInIdentity = context.Identity;
                if (!string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, signInIdentity);
            }

            if (context.IsRequestCompleted || context.RedirectUri == null) return context.IsRequestCompleted;
            if (context.Identity == null)
            {
                // add a redirect hint that sign-in failed in some way
                context.RedirectUri = WebUtilities.AddQueryString(context.RedirectUri, "error", "access_denied");
            }
            Response.Redirect(context.RedirectUri);
            context.RequestCompleted();

            return context.IsRequestCompleted;
        }
    }
}