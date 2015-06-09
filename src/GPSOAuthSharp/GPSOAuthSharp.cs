using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

namespace DankMemes.GPSOAuthSharp
{
    // gpsoauth:__init__.py
    // URL: https://github.com/simon-weber/gpsoauth/blob/master/gpsoauth/__init__.py
    class GPSOAuthClient
    {
        static string b64Key = "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3" +
            "iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pK" +
            "RI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/" +
            "6rmf5AAAAAwEAAQ==";
        static RSAParameters androidKey = GoogleKeyUtils.KeyFromB64(b64Key);

        static string version = "0.0.2";
        static string authUrl = "https://android.clients.google.com/auth";
        static string userAgent = "gpsoauth/" + version;

        private string email;
        private string password;

        public GPSOAuthClient(string email, string password)
        {
            this.email = email;
            this.password = password;
        }

        // _perform_auth_request
        private Dictionary<string, string> PerformAuthRequest(Dictionary<string, string> data)
        {
            FormUrlEncodedContent content = new FormUrlEncodedContent(data);
            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent);
                HttpResponseMessage response = client.PostAsync(new Uri(authUrl), content).Result;
                string result = response.Content.ReadAsStringAsync().Result;
                return GoogleKeyUtils.ParseAuthResponse(result);
            }
        }

        // perform_master_login
        public Dictionary<string, string> PerformMasterLogin(string service = "ac2dm", 
            string deviceCountry = "us", string operatorCountry = "us", string lang = "en", int sdkVersion = 17)
        {
            string signature = GoogleKeyUtils.CreateSignature(email, password, androidKey);
            var dict = new Dictionary<string, string> {
                { "accountType", "HOSTED_OR_GOOGLE" },
                { "Email", email },
                { "has_permission", 1.ToString() },
                { "add_account", 1.ToString() },
                { "EncryptedPasswd",  signature},
                { "service", service },
                { "source", "android" },
                { "device_country", deviceCountry },
                { "operatorCountry", operatorCountry },
                {"lang", lang },
                {"sdk_version", sdkVersion.ToString() }
            };
            return PerformAuthRequest(dict);
        }

        public Dictionary<string, string> PerformOAuth(string masterToken, string service, string app, string clientSig,
            string deviceCountry = "us", string operatorCountry = "us", string lang = "en", int sdkVersion = 17)
        {
            string signature = GoogleKeyUtils.CreateSignature(email, password, androidKey);
            var dict = new Dictionary<string, string> {
                { "accountType", "HOSTED_OR_GOOGLE" },
                { "Email", email },
                { "has_permission", 1.ToString() },
                { "EncryptedPasswd",  masterToken},
                { "service", service },
                { "source", "android" },
                { "app", app },
                { "client_sig", clientSig },
                { "device_country", deviceCountry },
                { "operatorCountry", operatorCountry },
                {"lang", lang },
                {"sdk_version", sdkVersion.ToString() }
            };
            return PerformAuthRequest(dict);
        }
    }

    // gpsoauth:google.py
    // URL: https://github.com/simon-weber/gpsoauth/blob/master/gpsoauth/google.py
    class GoogleKeyUtils
    {
        // key_from_b64
        // BitConverter has different endianness, hence the Reverse()
        public static RSAParameters KeyFromB64(string b64Key)
        {
            byte[] decoded = Convert.FromBase64String(b64Key);
            byte[] part1 = decoded.Take(4).ToArray();
            int i = BitConverter.ToInt32(part1.Reverse().ToArray(), 0);
            byte[] mod = decoded.Skip(4).Take((int)i).ToArray();
            byte[] part3 = decoded.Skip((int)i + 4).Take(4).ToArray();
            int j = BitConverter.ToInt32(part3.Reverse().ToArray(), 0); ;
            byte[] exponent = decoded.Skip((int)i + 8).Take((int)j).ToArray();
            RSAParameters rsaKeyInfo = new RSAParameters();
            rsaKeyInfo.Modulus = mod;
            rsaKeyInfo.Exponent = exponent;
            return rsaKeyInfo;
        }

        // key_to_struct
        // Python version returns a string, but we use byte[] to get the same results
        public static byte[] KeyToStruct(RSAParameters key)
        {
            byte[] begin = { 0x00, 0x00, 0x00, 0x80 };
            byte[] mod = key.Modulus;
            byte[] middle = { 0x00, 0x00, 0x00, 0x03 };
            byte[] exp = key.Exponent;
            return DataTypeUtils.CombineBytes(begin, mod, middle, exp);
        }

        // parse_auth_response
        public static Dictionary<string, string> ParseAuthResponse(string text)
        {
            Dictionary<string, string> responseData = new Dictionary<string, string>();
            foreach (string line in text.Split(new string[] { "\n", "\r\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                string[] parts = line.Split('=');
                if (!responseData.ContainsKey(parts[0]))
                {
                    if (string.IsNullOrEmpty(parts[1]))
                    {
                        responseData.Add(parts[0], null);
                    }
                    else
                    {
                        responseData.Add(parts[0], parts[1]);
                    }
                }
            }
            return responseData;
        }

        // signature
        public static string CreateSignature(string email, string password, RSAParameters key)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(key);
            SHA1 sha1 = SHA1.Create();

            List<byte> signature = new List<byte>();
            signature.Add(0x00);
            byte[] hash = sha1.ComputeHash(GoogleKeyUtils.KeyToStruct(key)).Take(4).ToArray();
            signature.AddRange(hash);
            byte[] encrypted = rsa.Encrypt(Encoding.UTF8.GetBytes(email + "\x00" + password), true);
            signature.AddRange(encrypted);
            return DataTypeUtils.UrlSafeBase64(signature.ToArray());
        }
    }

    class DataTypeUtils
    {
        public static string UrlSafeBase64(byte[] byteArray)
        {
            return Convert.ToBase64String(byteArray).Replace('+', '-').Replace('/', '_');
        }

        public static byte[] CombineBytes(params byte[][] arrays)
        {
            byte[] rv = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;
            foreach (byte[] array in arrays)
            {
                Buffer.BlockCopy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }
            return rv;
        }
    }
}
