using System;
using System.Text;
using System.Collections.Specialized;
using System.Web.Script.Serialization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using System.Runtime.InteropServices;


namespace GoogleAuth_P12
{

    [Guid("87377FB4-E5D8-43CD-884B-947F612C84D0")]
    internal interface IGoogleJsonWebToken
    {
        [DispId(1)]
        // описываем методы которые можно будет вызывать из вне        
        string GetAccessToken(string clientIdEMail, string keyFilePath, string scope, string proxyUrl = "", int proxyPort = 0, string proxyUser = "", string proxyPsw = "");
    }
    [Guid("3289EB18-AF34-4A6B-A7DA-101B57782EAD"), InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
    public interface IMyEvents
    {
    }

    [Guid("292758BB-DBC7-47EE-9B3B-4720EEBCC0F6"), ClassInterface(ClassInterfaceType.None), ComSourceInterfaces(typeof(IMyEvents))]
    public class GoogleJsonWebToken : IGoogleJsonWebToken
    {
        public string GetAccessToken(string clientIdEMail, string keyFilePath, string scope, string proxyUrl = "", int proxyPort = 0, string proxyUser = "", string proxyPsw = "")
        {
            // certificate
            var certificate = new X509Certificate2(keyFilePath, "notasecret");

            // header
            var header = new { typ = "JWT", alg = "RS256" };

            // claimset
            var times = GetExpiryAndIssueDate();
            var claimset = new
            {
                iss = clientIdEMail,
                scope = scope,
                aud = "https://accounts.google.com/o/oauth2/token",
                iat = times[0],
                exp = times[1],
            };

            JavaScriptSerializer ser = new JavaScriptSerializer();

            // encoded header
            var headerSerialized = ser.Serialize(header);
            var headerBytes = Encoding.UTF8.GetBytes(headerSerialized);
            var headerEncoded = Convert.ToBase64String(headerBytes);

            // encoded claimset
            var claimsetSerialized = ser.Serialize(claimset);
            var claimsetBytes = Encoding.UTF8.GetBytes(claimsetSerialized);
            var claimsetEncoded = Convert.ToBase64String(claimsetBytes);

            // input
            var input = headerEncoded + "." + claimsetEncoded;
            var inputBytes = Encoding.UTF8.GetBytes(input);

            // signiture
            var rsa = certificate.PrivateKey as RSACryptoServiceProvider;
            var cspParam = new CspParameters
            {
                KeyContainerName = rsa.CspKeyContainerInfo.KeyContainerName,
                KeyNumber = rsa.CspKeyContainerInfo.KeyNumber == KeyNumber.Exchange ? 1 : 2
            };
            var aescsp = new RSACryptoServiceProvider(cspParam) { PersistKeyInCsp = false };
            var signatureBytes = aescsp.SignData(inputBytes, "SHA256");
            var signatureEncoded = Convert.ToBase64String(signatureBytes);

            // jwt
            var jwt = headerEncoded + "." + claimsetEncoded + "." + signatureEncoded;

            var client = new WebClient();
            client.Encoding = Encoding.UTF8;
            client.UseDefaultCredentials = true;
            client.Proxy = WebRequest.GetSystemWebProxy();
            if (proxyUrl != "")
            {
                //"srv-tmg.volna.dmn"
                //3128
                WebProxy proxy = new WebProxy(proxyUrl, proxyPort);
                if (proxyUser != "")
                {
                    proxy.Credentials = new NetworkCredential(proxyUser, proxyPsw);
                }
                client.Proxy = proxy;
            }


            var uri = "https://accounts.google.com/o/oauth2/token";
            var content = new NameValueCollection();

            content["assertion"] = jwt;
            content["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer";

            string response = Encoding.UTF8.GetString(client.UploadValues(uri, "POST", content));

            //var result = ser.Deserialize<dynamic>(response);
            //return result;
            return response;
        }
        private static int[] GetExpiryAndIssueDate()
        {
            var utc0 = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var issueTime = DateTime.UtcNow;

            var iat = (int)issueTime.Subtract(utc0).TotalSeconds;
            var exp = (int)issueTime.AddMinutes(55).Subtract(utc0).TotalSeconds;

            return new[] { iat, exp };
        }
    }
}

