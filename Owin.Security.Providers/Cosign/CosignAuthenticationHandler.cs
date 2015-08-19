using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Providers.Cosign.Provider;

namespace Owin.Security.Providers.Cosign
{
    public class CosignAuthenticationHandler : AuthenticationHandler<CosignAuthenticationOptions>
    {
        /*
        Cosign sends authenticated users to iis web site root (not to application). 
        We need redirect user back to Identity Server application. 
        This can be done with different approaches http handler, url rewrite...
        Here is UrlRewrite configuration
        <rewrite>
            <rules>
                <clear />
                <rule name="Cosign-RedirectCore1" enabled="true" stopProcessing="true">
                    <match url="cosign/valid?" negate="false" />
                    <conditions logicalGrouping="MatchAll" trackAllCaptures="false">
                        <add input="{QUERY_STRING}" pattern="core=core1" />
                    </conditions>
                    <action type="Redirect" url="https://yourserver/host/path/signin-cosign" redirectType="SeeOther" />
                </rule>
                <rule name="Cosign-RedirectCore2" enabled="true" stopProcessing="true">
                    <match url="cosign/valid?" negate="false" />
                    <conditions logicalGrouping="MatchAll" trackAllCaptures="false">
                        <add input="{QUERY_STRING}" pattern="core=core2" />
                    </conditions>
                    <action type="Redirect" url="https://yourserver/host/path/signin-cosign" redirectType="SeeOther" />
                </rule>
            </rules>
        </rewrite>
        */
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private readonly ILogger logger;
 
        public CosignAuthenticationHandler(ILogger logger)
        {
 
            this.logger = logger;
        }

        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string serviceCookieValue = null;
                string state = null;

                /*BUG: IReadableStringCollection has a bug. Some charactes can be missed in the collection and replaces with blank space.
                Example: having "x" character in QueryString will result in having " " in the collection.
                I will use QueryString from Request object instead of IReadableStringCollection*/

                //IReadableStringCollection query = Request.Query;
                //IList<string> values = query.GetValues("cosign-" + Options.ClientServer);
                //if (values != null && values.Count == 1)
                //{
                //    serviceCookieValue = values[0];
                //}
                //values = query.GetValues("state");
                //if (values != null && values.Count == 1)
                //{
                //    state = values[0];
                //}

                string queryString = Request.QueryString.Value;
                string[] values = queryString.Split(new string[] {"&"}, StringSplitOptions.RemoveEmptyEntries);
                serviceCookieValue =
                    values.First(a => a.Contains(Options.ClientServer))
                        .Replace("cosign-" + Options.ClientServer + "=", "");
                state =
                    values.First(a => a.Contains("state"))
                        .Replace("state=", "");

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }


                //// OAuth2 10.12 CSRF
                //if (!ValidateCorrelationId(properties, logger))
                //{
                //    return new AuthenticationTicket(null, properties);
                //}


                // Get host related information.
                IPHostEntry hostEntry = Dns.GetHostEntry(Options.CosignServer);

                // Loop through the AddressList to obtain the supported AddressFamily. This is to avoid 
                // an exception that occurs when the host IP Address is not compatible with the address family 
                // (typical in the IPv6 case). 
                foreach (IPAddress address in hostEntry.AddressList)
                {
                    IPEndPoint ipLocalEndPoint = new IPEndPoint(address, Options.CosignServicePort);
             
                    using (TcpClient tcpClient = new TcpClient())
                    {

                        tcpClient.Connect(address, Options.CosignServicePort);
                        if (tcpClient.Connected)
                        {
                            logger.WriteInformation("Cosign authenticaion handler. Connected to server ip: " + address);

                            //read message from connected server and validate response 
                            NetworkStream networkStream = tcpClient.GetStream();
                            byte[] buffer = new byte[256];
                            var bytesRead = networkStream.ReadAsync(buffer, 0, buffer.Length);
                            var receivedData = Encoding.UTF8.GetString(buffer, 0, bytesRead.Result);
                            //expected message: 220 2 Collaborative Web Single Sign-On [COSIGNv3 FACTORS=5 REKEY]
                            if (receivedData.Substring(0, 3) != "220")
                                continue;

                            //initiate secure negotiation and validate resonse 
                            //buffer = Encoding.UTF8.GetBytes("STARTTLS 2\r\n");
                            buffer = Encoding.UTF8.GetBytes("STARTTLS 2" + Environment.NewLine);
                            networkStream.Write(buffer, 0, buffer.Length);
                            networkStream.Flush();
                            buffer = new byte[256];
                            bytesRead = networkStream.ReadAsync(buffer, 0, buffer.Length);
                            receivedData = Encoding.UTF8.GetString(buffer, 0, bytesRead.Result);
                            //expected message: 220 Ready to start TLS
                            if (receivedData.Substring(0, 3) != "220")
                                continue;


                            SslStream sslStream = new SslStream(tcpClient.GetStream(), false, ValidateServerCertificate,
                                null);

                            X509CertificateCollection certs = GetCertificateCertificateCollection(Options.ClientServer,
                                StoreName.My,
                                StoreLocation.LocalMachine);
                            try
                            {
                                Task authResult =  sslStream.AuthenticateAsClientAsync(Options.CosignServer, certs, SslProtocols.Tls, false);
                                 authResult.GetAwaiter().GetResult();
                            }
                            catch (AuthenticationException e)
                            {
                                logger.WriteError(e.Message);
                                if (e.InnerException != null)
                                {
                                    logger.WriteError(string.Format("Inner exception: {0}", e.InnerException.Message));
                                }
                                logger.WriteError("Authentication failed - closing the connection.");
                                tcpClient.Close();
                                continue;
                            }
                            catch (Exception ex)
                            {
                                logger.WriteError(ex.Message);
                                tcpClient.Close();
                                continue;
                            }
                          
                            if (!sslStream.IsEncrypted || !sslStream.IsSigned || !sslStream.IsMutuallyAuthenticated)
                                continue;
                            // The server name must match the name on the server certificate.
                            if (!sslStream.IsAuthenticated)
                                continue;


                            buffer = new byte[256];
                            bytesRead = sslStream.ReadAsync(buffer, 0, buffer.Length);
                            receivedData = Encoding.UTF8.GetString(buffer, 0, bytesRead.Result);
                            //expected message: 220 2 Collaborative Web Single Sign-On [COSIGNv3 FACTORS=5 REKEY]
                            if (receivedData.Substring(0, 3) != "220")
                                continue;

                            byte[] data =
                                Encoding.UTF8.GetBytes("CHECK " + "cosign-" + Options.ClientServer + "=" +
                                                       serviceCookieValue + Environment.NewLine);

                            sslStream.Write(data, 0, data.Length);
                            sslStream.Flush();
                            buffer = new byte[256];

                            bytesRead = sslStream.ReadAsync(buffer, 0, buffer.Length);
                            receivedData = Encoding.UTF8.GetString(buffer, 0, bytesRead.Result);


                            switch (receivedData.Substring(0, 1))
                            {
                                case "2":
                                    //Success
                                    logger.WriteInformation("Cosign authenticaion handler. 2-Response from Server: Success.");
                                    var context = new CosignAuthenticatedContext(Context, receivedData)
                                    {
                                        Identity = new ClaimsIdentity(
                                            Options.AuthenticationType,
                                            ClaimsIdentity.DefaultNameClaimType,
                                            ClaimsIdentity.DefaultRoleClaimType)
                                    };


                                    var identity = new ClaimsIdentity(Options.SignInAsAuthenticationType);
                                    if (!string.IsNullOrEmpty(context.Id))
                                    {
                                        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id,
                                            XmlSchemaString, Options.AuthenticationType));
                                    }
                                    if (!string.IsNullOrEmpty(context.UserId))
                                    {
                                        identity.AddClaim(new Claim("UserId", context.UserId, XmlSchemaString,
                                            Options.AuthenticationType));
                                    }
                                    if (!string.IsNullOrEmpty(context.IpAddress))
                                    {
                                        identity.AddClaim(new Claim("IpAddress", context.IpAddress, XmlSchemaString,
                                            Options.AuthenticationType));
                                    }
                                    if (!string.IsNullOrEmpty(context.Realm))
                                    {
                                        identity.AddClaim(new Claim("Realm", context.Realm, XmlSchemaString,
                                            Options.AuthenticationType));
                                    }

                                    context.Properties = properties;

                                    return Task.FromResult(new AuthenticationTicket(identity, properties));


                                case "4":
                                    //Logged out
                                    logger.WriteInformation("Cosign authenticaion handler. Response from Server: 4-Logged out.");
                                    break;
                                case "5":
                                    //Try a different server
                                    logger.WriteInformation("Cosign authenticaion handler. Response from Server: 5-Try different server.");
                                    break;
                                default:
                                    logger.WriteInformation("Cosign authenticaion handler. Response from Server: Undefined.");
                                    break;

                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                logger.WriteError(ex.Message);
            }


            return Task.FromResult(new AuthenticationTicket(null, properties));
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

                // Only react to 401 if there is an authentication challenge for the authentication 
                // type of this handler.
                if (challenge != null)
                {
                    var state = challenge.Properties;

                    if (string.IsNullOrEmpty(state.RedirectUri))
                    {
                        state.RedirectUri = Request.Uri.ToString();
                    }

                    var stateString = Options.StateDataFormat.Protect(state);

                    string loginUrl =
                        "https://" + Options.CosignServer + "/?cosign-" + Options.ClientServer +
                        "&state=" + Uri.EscapeDataString(stateString) +
                        "&core=" + Options.IdentityServerHostInstance;
                    logger.WriteInformation("Cosign authenticaion handler. Redirecting to cosign. " + loginUrl);
                    Response.Redirect(loginUrl);
                }
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            // This is always invoked on each request. For passive middleware, only do anything if this is
            // for our callback path when the user is redirected back from the authentication provider.
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                var ticket = await AuthenticateAsync();

                if (ticket != null)
                {
                    Context.Authentication.SignIn(ticket.Properties, ticket.Identity);

                    Response.Redirect(ticket.Properties.RedirectUri);

                    // Prevent further processing by the owin pipeline.
                    return true;
                }
            }
            // Let the rest of the pipeline run.
            return false;
        }


        public static X509CertificateCollection GetCertificateCertificateCollection(string subjectName,
            StoreName storeName,
            StoreLocation storeLocation)
        {
            // The following code gets the cert from the keystore
            X509Store store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certCollection =
                store.Certificates.Find(X509FindType.FindBySubjectName,
                    subjectName,
                    false);
            return certCollection;
        }

        private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            return false;
        }
    }
}