using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace DropBox.Services
{
    public class Authentication
    {
        private string _apiKey;
        private string _apiSecret;

        public Authentication(string key, string secret) { 
        
            _apiKey = key;
            _apiSecret = secret;

        }

        public async Task<OAuthToken> RequestToken(string url, string callbackUrl) { 
        

                TimeSpan SinceEpoch = (DateTime.Now - new DateTime(1970, 1, 1, 0, 0, 0, 0).ToLocalTime());
                Random Rand = new Random();
              
                Int32 Nonce = Rand.Next(1000000000);
               
                String sigBaseStringParams = "oauth_callback=" + Uri.EscapeDataString(callbackUrl);
                sigBaseStringParams += "&" + "oauth_consumer_key=" + _apiKey;
                sigBaseStringParams += "&" + "oauth_nonce=" + Nonce.ToString();
                sigBaseStringParams += "&" + "oauth_signature_method=HMAC-SHA1";
                sigBaseStringParams += "&" + "oauth_timestamp=" + Math.Round(SinceEpoch.TotalSeconds);
                sigBaseStringParams += "&" + "oauth_version=1.0";
                String SigBaseString = "POST&";
                SigBaseString += Uri.EscapeDataString(url) + "&" + Uri.EscapeDataString(sigBaseStringParams);
                var signature = GenerateSignature(SigBaseString, _apiSecret);

                String DataToPost = "OAuth oauth_callback=\"" + Uri.EscapeDataString(callbackUrl) + "\", oauth_consumer_key=\"" + _apiKey + "\", oauth_nonce=\"" + Nonce.ToString() + "\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"" + Math.Round(SinceEpoch.TotalSeconds) + "\", oauth_version=\"1.0\", oauth_signature=\"" + Uri.EscapeDataString(signature) + "\"";

                var postResponse =  await PostData(url, DataToPost);
            
                if (postResponse != null)
                {
                    String oauth_token = null;
                    String oauth_token_secret = null;
                    String[] keyValPairs = postResponse.Split('&');

                    for (int i = 0; i < keyValPairs.Length; i++)
                    {
                        String[] splits = keyValPairs[i].Split('=');
                        switch (splits[0])
                        {
                            case "oauth_token":
                                oauth_token = splits[1];
                                break;
                            case "oauth_token_secret":
                                oauth_token_secret = splits[1];
                                break;
                        }
                    }
                    return new OAuthToken(oauth_token, oauth_token_secret);
                }

                return null;

        }

        private async Task<string> PostData(String Url, String Data)
        {

            HttpWebRequest Request = (HttpWebRequest)WebRequest.Create(Url);
            Request.Method = "POST";
            Request.Headers["Authorization"] = Data;
            HttpWebResponse Response = (HttpWebResponse)await Request.GetResponseAsync();
            StreamReader ResponseDataStream = new StreamReader(Response.GetResponseStream());
            return ResponseDataStream.ReadToEnd();

        }




        private  string GenerateSignature(String SigBaseString, string secret)
        {

            IBuffer KeyMaterial = CryptographicBuffer.ConvertStringToBinary(secret + "&", BinaryStringEncoding.Utf8);
            MacAlgorithmProvider HmacSha1Provider = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");
            CryptographicKey MacKey = HmacSha1Provider.CreateKey(KeyMaterial);
            IBuffer DataToBeSigned = CryptographicBuffer.ConvertStringToBinary(SigBaseString, BinaryStringEncoding.Utf8);
            IBuffer SignatureBuffer = CryptographicEngine.Sign(MacKey, DataToBeSigned);
            String Signature = CryptographicBuffer.EncodeToBase64String(SignatureBuffer);
            return Signature;
        }

        public async void GetAccessToken(string url, string key, string secret)
        {
            TimeSpan SinceEpoch = (DateTime.Now - new DateTime(1970, 1, 1, 0, 0, 0, 0).ToLocalTime());
            Random Rand = new Random();

            Int32 Nonce = Rand.Next(1000000000);

            String sigBaseStringParams = "oauth_consumer_key=" + _apiKey;        
            sigBaseStringParams += "&" + "oauth_nonce=" + Nonce.ToString();
            sigBaseStringParams += "&" + "oauth_signature_method=HMAC-SHA1";
            sigBaseStringParams += "&" + "oauth_timestamp=" + Math.Round(SinceEpoch.TotalSeconds);       
            sigBaseStringParams += "&" + "oauth_version=1.0";
            String SigBaseString = "POST&";
            SigBaseString += Uri.EscapeDataString(url) + "&" + Uri.EscapeDataString(sigBaseStringParams);
            var signature = GenerateSignature(SigBaseString, secret);

            String DataToPost = "OAuth oauth_consumer_key=\"" + _apiKey + "\", oauth_nonce=\"" + Nonce.ToString() + "\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"" + Math.Round(SinceEpoch.TotalSeconds) + "\", oauth_version=\"1.0\", oauth_signature=\"" + Uri.EscapeDataString(signature) + "\"";

            var postResponse = await PostData(url, DataToPost);
        }
    }

    public class OAuthToken
    {
        
        private string _key;
        private string _secret;

        public OAuthToken(string key, string secret)
        {
            _key = key;
            _secret = secret;
        }

        public string Key { get {return _key;}}
        public string Secret { get { return _secret;}}

    }
}
