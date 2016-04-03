using ApiMkm.Configuration;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace ApiMkm
{
    public enum httpMethod
    {
        GET,
        POST,
        PUT,
        DELETE,
    }

    public class ApiMkm : IDisposable
    {
        HttpWebRequest httpWebRequest { get; set; }
        OAuthHeader header { get; set; }
        HttpWebResponse response { get; set; }

        #region Initialize
        static string _appToken { get; set; }
        static string _appSecret { get; set; }
        static string _accessToken { get; set; }
        static string _accessSecret { get; set; }

        public static void Initialize(string appToken, string appSecret, string accessToken, string accessSecret)
        {
            _appToken = appToken;
            _appSecret = appSecret;
            _accessToken = accessToken;
            _accessSecret = accessSecret;
        }

        public static void XmlConfiguration(MkmAuthTokenSection section)
        {
            Initialize(section.AppToken, section.AppSecret, section.AccessToken, section.AccessSecret);
        }
        #endregion

        /// <summary>
        /// Renvoie le résultat obtenu sur MKM de l'url souhaité.
        /// </summary>
        /// <param name="url">url</param>
        /// <returns>résultat</returns>
        public static XmlDocument Get(string url)
        {
            using (var api = new ApiMkm())
            {
                XmlDocument doc = new XmlDocument();
                doc.Load(api.SendRequest(url, httpMethod.POST).GetResponseStream());
                return doc;
            }
        }

        /// <summary>
        /// Permet de POST du contenu sur le site
        /// </summary>
        /// <param name="url"></param>
        /// <param name="dataToPost"></param>
        public static void Post(string url, string dataToPost)
        {
            using (var api = new ApiMkm())
            {
                api.SendRequest(url, httpMethod.POST, dataToPost);
            }
        }

        /// <summary>
        /// Permet de PUT du contenu sur le site
        /// </summary>
        /// <param name="url"></param>
        /// <param name="dataToPost"></param>
        public static void Put(string url, string dataToPost)
        {
            using (var api = new ApiMkm())
            {
                api.SendRequest(url, httpMethod.PUT, dataToPost);
            }
        }

        private HttpWebResponse SendRequest(string url, httpMethod httpMethod, string postData = "")
        {
            try
            {
                string method = httpMethod.ToString().ToUpper();
                this.httpWebRequest = WebRequest.Create(url) as HttpWebRequest;
                this.httpWebRequest.ProtocolVersion = HttpVersion.Version10; // l'api MKM 1.1 supporte le protocole 1.0 seulement
                this.header = new OAuthHeader(ApiMkm._appToken, ApiMkm._appSecret, ApiMkm._accessToken, ApiMkm._accessSecret);
                this.httpWebRequest.Headers.Add(HttpRequestHeader.Authorization, header.getAuthorizationHeader(method, url));
                this.httpWebRequest.Method = method;

                if (!string.IsNullOrEmpty(postData) && (httpMethod == httpMethod.PUT || httpMethod == httpMethod.POST))
                {
                    XmlDocument soapEnvelopXml = new XmlDocument();
                    soapEnvelopXml.LoadXml(postData);
                    using (Stream stream = httpWebRequest.GetRequestStream())
                    {
                        soapEnvelopXml.Save(stream);
                    }
                    httpWebRequest.ContentType = "application/xml;charset=\"utf-8\"";
                    httpWebRequest.Accept = "application/json,application/xml";
                }

                return this.httpWebRequest.GetResponse() as HttpWebResponse;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        #region Dispose
        public void Dispose()
        {
            Dispose(true);
        }

        public void Dispose(bool isDisposing)
        {
            if (isDisposing)
            {
                if (this.httpWebRequest != null)
                    this.httpWebRequest = null;
                if (this.header != null)
                    this.header = null;
                if (this.response != null)
                {
                    this.response.Dispose();
                    this.response = null;
                }
            }
        }
        #endregion
    }

    class OAuthHeader
    {
        private string _appToken { get; set; }
        private string _appSecret { get; set; }
        private string _accessToken { get; set; }
        private string _accessSecret { get; set; }

        private const string signatureMethod = "HMAC-SHA1";

        private const string version = "1.0";

        private IDictionary<string, string> headerParams { get; set; }

        public OAuthHeader(string appToken, string appSecret, string accessToken, string accessSecret)
        {
            _appToken = appToken;
            _appSecret = appSecret;
            _accessToken = accessToken;
            _accessSecret = accessSecret;

            string nonce = "53eb1f44909d6"; // Guid.NewGuid().ToString("n");
            string timestamp = "1407917892"; // DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds.ToString();

            this.headerParams = new Dictionary<String, String>();
            this.headerParams.Add("oauth_consumer_key", this._appToken);
            this.headerParams.Add("oauth_token", this._accessToken);
            this.headerParams.Add("oauth_nonce", nonce);
            this.headerParams.Add("oauth_timestamp", timestamp);
            this.headerParams.Add("oauth_signature_method", signatureMethod);
            this.headerParams.Add("oauth_version", version);
        }

        /// <summary>
        /// Pass request method and URI parameters to get the Authorization header value
        /// </summary>
        /// <param name="method">Request Method</param>
        /// <param name="url">Request URI</param>
        /// <returns>Authorization header value</returns>
        public String getAuthorizationHeader(string method, string url)
        {
            /// Add the realm parameter to the header params
            this.headerParams.Add("realm", url);

            /// Start composing the base string from the method and request URI
            //string baseString = string.Format("{0}&{1}&", method.ToUpper(), Uri.EscapeDataString(url));
            string baseString = method.ToUpper()
                              + "&"
                              + Uri.EscapeDataString(url)
                              + "&";

            /// Gather, encode, and sort the base string parameters
            SortedDictionary<String, String> encodedParams = new SortedDictionary<String, String>();
            foreach (KeyValuePair<String, String> parameter in this.headerParams)
            {
                if (false == parameter.Key.Equals("realm"))
                {
                    encodedParams.Add(Uri.EscapeDataString(parameter.Key), Uri.EscapeDataString(parameter.Value));
                }
            }

            /// Expand the base string by the encoded parameter=value pairs
            List<String> paramStrings = new List<String>();
            foreach (KeyValuePair<String, String> parameter in encodedParams)
            {
                paramStrings.Add(parameter.Key + "=" + parameter.Value);
            }
            String paramString = Uri.EscapeDataString(String.Join<String>("&", paramStrings));
            baseString += paramString;

            /// Create the OAuth signature
            String signatureKey = Uri.EscapeDataString(this._appSecret) + "&" + Uri.EscapeDataString(this._accessSecret);
            HMAC hasher = HMACSHA1.Create();
            hasher.Key = Encoding.UTF8.GetBytes(signatureKey);
            Byte[] rawSignature = hasher.ComputeHash(Encoding.UTF8.GetBytes(baseString));
            String oAuthSignature = System.Convert.ToBase64String(rawSignature);

            /// Include the OAuth signature parameter in the header parameters array
            this.headerParams.Add("oauth_signature", oAuthSignature);

            /// Construct the header string
            List<String> headerParamStrings = new List<String>();
            foreach (KeyValuePair<String, String> parameter in this.headerParams)
            {
                headerParamStrings.Add(parameter.Key + "=\"" + parameter.Value + "\"");
            }
            String authHeader = "OAuth " + String.Join<String>(", ", headerParamStrings);

            return authHeader;
        }
    }
}

