using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace Owin.Security.Providers.Evernote
{
    internal sealed class OAuthBase
    {
        private readonly Random _random = new Random();
        private readonly string _unreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
        private const string OAuthConsumerKey = "oauth_consumer_key";
        private const string OAuthCallbackKey = "oauth_callback";
        private const string OAuthSignatureMethodKey = "oauth_signature_method";
        private const string OAuthTimestampKey = "oauth_timestamp";
        private const string OAuthNonceKey = "oauth_nonce";
        private const string OAuthTokenKey = "oauth_token";
        private const string OAuthVerifierKey = "oauth_verifier";
        private const string Hmacsha1SignatureType = "HMAC-SHA1";
        private const string PlainTextSignatureType = "PLAINTEXT";

        private string ComputeHash(HashAlgorithm hashAlgorithm, string data)
        {
            if (hashAlgorithm == null)
                throw new ArgumentNullException("hashAlgorithm");
            if (string.IsNullOrEmpty(data))
                throw new ArgumentNullException("data");
            byte[] bytes = Encoding.ASCII.GetBytes(data);
            return Convert.ToBase64String(hashAlgorithm.ComputeHash(bytes));
        }

        private List<QueryParameter> GetQueryParameters(string parameters)
        {
            if (parameters.StartsWith("?"))
                parameters = parameters.Remove(0, 1);
            List<QueryParameter> queryParameterList = new List<QueryParameter>();
            if (!string.IsNullOrEmpty(parameters))
            {
                string str = parameters;
                char[] chArray = { '&' };
                foreach (string name in str.Split(chArray))
                {
                    if (!string.IsNullOrEmpty(name) && !name.StartsWith("oauth_"))
                    {
                        if (name.IndexOf('=') > -1)
                        {
                            string[] strArray = name.Split('=');
                            queryParameterList.Add(new QueryParameter(strArray[0], strArray[1]));
                        }
                        else
                            queryParameterList.Add(new QueryParameter(name, string.Empty));
                    }
                }
            }
            return queryParameterList;
        }

        private string UrlEncode(string value)
        {
            var stringBuilder = new StringBuilder();
            foreach (char ch in value)
            {
                if (_unreservedChars.IndexOf(ch) != -1)
                    stringBuilder.Append(ch);
                else
                    stringBuilder.Append(37 + $"{(int) ch:X2}");
            }
            return stringBuilder.ToString();
        }

        private string NormalizeRequestParameters(IList<QueryParameter> parameters)
        {
            StringBuilder stringBuilder = new StringBuilder();
            for (int index = 0; index < parameters.Count; ++index)
            {
                QueryParameter queryParameter = parameters[index];
                stringBuilder.AppendFormat("{0}={1}", queryParameter.Name, queryParameter.Value);
                if (index < parameters.Count - 1)
                    stringBuilder.Append("&");
            }
            return stringBuilder.ToString();
        }

        private string GenerateSignatureBase(Uri url, string consumerKey, string token, string verifier, string httpMethod, string timeStamp, string nonce, string callback, string signatureType, out string normalizedUrl, out string normalizedRequestParameters)
        {
            if (token == null)
                token = string.Empty;
            if (string.IsNullOrEmpty(consumerKey))
                throw new ArgumentNullException("consumerKey");
            if (string.IsNullOrEmpty(httpMethod))
                throw new ArgumentNullException("httpMethod");
            if (string.IsNullOrEmpty(signatureType))
                throw new ArgumentNullException("signatureType");

            List<QueryParameter> queryParameters = GetQueryParameters(url.Query);
            queryParameters.Add(new QueryParameter(OAuthConsumerKey, consumerKey));
            queryParameters.Add(new QueryParameter(OAuthSignatureMethodKey, signatureType));
            queryParameters.Add(new QueryParameter(OAuthTimestampKey, timeStamp));
            queryParameters.Add(new QueryParameter(OAuthNonceKey, nonce));

            if (!string.IsNullOrEmpty(callback))
                queryParameters.Add(new QueryParameter(OAuthCallbackKey, callback));
            if (!string.IsNullOrEmpty(token))
                queryParameters.Add(new QueryParameter(OAuthTokenKey, token));
            if (!string.IsNullOrEmpty(verifier))
                queryParameters.Add(new QueryParameter(OAuthVerifierKey, verifier));

            normalizedUrl = $"{url.Scheme}://{url.Host}";
            normalizedUrl += url.AbsolutePath;
            normalizedRequestParameters = NormalizeRequestParameters(queryParameters);

            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.AppendFormat("{0}&", httpMethod.ToUpperInvariant());
            stringBuilder.AppendFormat("{0}&", UrlEncode(normalizedUrl));
            stringBuilder.AppendFormat("{0}", UrlEncode(normalizedRequestParameters));

            return stringBuilder.ToString();
        }

        private string GenerateSignatureUsingHash(string signatureBase, HashAlgorithm hash)
        {
            return ComputeHash(hash, signatureBase);
        }

        public string GenerateSignature(Uri url, string consumerKey, string consumerSecret, string token, string verifier, string httpMethod, string timeStamp, string nonce, string callback, out string normalizedUrl, out string normalizedRequestParameters)
        {
            return GenerateSignature(url, consumerKey, consumerSecret, token, verifier, httpMethod, timeStamp, nonce, callback, SignatureTypes.Plaintext, out normalizedUrl, out normalizedRequestParameters);
        }

        public string GenerateSignature(Uri url, string consumerKey, string consumerSecret, string token, string verifier, string httpMethod, string timeStamp, string nonce, string callback, SignatureTypes signatureType, out string normalizedUrl, out string normalizedRequestParameters)
        {
            normalizedUrl = null;
            normalizedRequestParameters = null;
            switch (signatureType)
            {
                case SignatureTypes.Hmacsha1:
                    var signatureBase = GenerateSignatureBase(url, consumerKey, token, verifier, httpMethod, timeStamp, nonce, callback, Hmacsha1SignatureType, out normalizedUrl, out normalizedRequestParameters);
                    var hmacshA1 = new HMACSHA1
                    {
                        Key = Encoding.ASCII.GetBytes($"{UrlEncode(consumerSecret)}&{UrlEncode(verifier)}")
                    };
                    return GenerateSignatureUsingHash(signatureBase, hmacshA1);
                case SignatureTypes.Plaintext:
                    GenerateSignatureBase(url, consumerKey, token, verifier, httpMethod, timeStamp, nonce, callback, PlainTextSignatureType, out normalizedUrl, out normalizedRequestParameters);
                    return HttpUtility.UrlEncode($"{consumerSecret}&{verifier}");
                case SignatureTypes.Rsasha1:
                    throw new NotImplementedException();
                default:
                    throw new ArgumentException(@"Unknown signature type", nameof(signatureType));
            }
        }

        public string GenerateTimeStamp()
        {
            return Convert.ToInt64((DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0)).TotalSeconds).ToString();
        }

        public string GenerateNonce()
        {
            return _random.Next(123400, 9999999).ToString();
        }

        private class QueryParameter
        {
            public string Name { get; }

            public string Value { get; }

            public QueryParameter(string name, string value)
            {
                Name = name;
                Value = value;
            }
        }
    }
}
