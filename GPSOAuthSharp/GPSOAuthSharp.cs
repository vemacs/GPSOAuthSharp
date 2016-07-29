using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DankMemes.GPSOAuthSharp
{
    // gpsoauth:__init__.py
    // URL: https://github.com/simon-weber/gpsoauth/blob/master/gpsoauth/__init__.py
    public class GPSOAuthClient
    {
        static string b64Key = "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3" +
            "iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pK" +
            "RI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/" +
            "6rmf5AAAAAwEAAQ==";
        static RSAParameters androidKey = GoogleKeyUtils.KeyFromB64(b64Key);

        static string version = "0.0.5";
        static string authUrl = "https://android.clients.google.com/auth";
        static string userAgent = "GPSOAuthSharp/" + version;

        private string email;
        private string password;

        public GPSOAuthClient(string email, string password)
        {
            this.email = email;
            this.password = password;
        }

        // _perform_auth_request
        private async static Task<IDictionary<string, string>> PerformAuthRequestAsync(IDictionary<string, string> data)
        {
            var handler = new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.GZip,
                AllowAutoRedirect = false
            };
            using (var tempHttpClient = new HttpClient(handler))
            {
                tempHttpClient.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent);

                HttpResponseMessage response;
                using (var formUrlEncodedContent = new FormUrlEncodedContent(data))
                {
                    response = await tempHttpClient.PostAsync(authUrl, formUrlEncodedContent).ConfigureAwait(false);
                }

                var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                return GoogleKeyUtils.ParseAuthResponse(content);
            }
        }

        private static IDictionary<string, string> GenerateBaseRequest(
            string email,
            string encryptedPassword,
            string service,
            string deviceCountry,
            string operatorCountry,
            string lang,
            int sdkVersion)
             => new Dictionary<string, string> {
                { "accountType", "HOSTED_OR_GOOGLE" },
                { "Email", email },
                { "has_permission", "1" },
                { "EncryptedPasswd",  encryptedPassword},
                { "service", service },
                { "source", "android" },
                { "device_country", deviceCountry },
                { "operatorCountry", operatorCountry },
                { "lang", lang },
                { "sdk_version", sdkVersion.ToString() }
    };

        // perform_master_login
        public Task<IDictionary<string, string>> PerformMasterLoginAsync(string service = "ac2dm",
            string deviceCountry = "us", string operatorCountry = "us", string lang = "en", int sdkVersion = 21)
        {
            var signature = GoogleKeyUtils.CreateSignature(email, password, androidKey);
            var request = GenerateBaseRequest(email, signature, service, deviceCountry, operatorCountry, lang, sdkVersion);
            request.Add("add_account", "1");
            return PerformAuthRequestAsync(request);
        }

        // perform_oauth
        public Task<IDictionary<string, string>> PerformOAuthAsync(string masterToken, string service, string app, string clientSig,
            string deviceCountry = "us", string operatorCountry = "us", string lang = "en", int sdkVersion = 21)
        {
            var request = GenerateBaseRequest(email, masterToken, service, deviceCountry, operatorCountry, lang, sdkVersion);
            request.Add("app", app);
            request.Add("client_sig", clientSig);
            return PerformAuthRequestAsync(request);
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
            var decoded = Convert.FromBase64String(b64Key);
            var modLength = BitConverter.ToInt32(decoded.Take(4).Reverse().ToArray(), 0);
            var mod = decoded.Skip(4).Take(modLength).ToArray();
            var expLength = BitConverter.ToInt32(decoded.Skip(modLength + 4).Take(4).Reverse().ToArray(), 0);
            var exponent = decoded.Skip(modLength + 8).Take(expLength).ToArray();
            var rsaKeyInfo = new RSAParameters
            {
                Modulus = mod,
                Exponent = exponent
            };
            return rsaKeyInfo;
        }

        // key_to_struct
        // Python version returns a string, but we use byte[] to get the same results
        public static byte[] KeyToStruct(RSAParameters key)
        {
            byte[] modLength = { 0x00, 0x00, 0x00, 0x80 };
            var mod = key.Modulus;
            byte[] expLength = { 0x00, 0x00, 0x00, 0x03 };
            var exponent = key.Exponent;
            return DataTypeUtils.CombineBytes(modLength, mod, expLength, exponent);
        }

        // parse_auth_response
        public static Dictionary<string, string> ParseAuthResponse(string text)
        {
            var responseData = new Dictionary<string, string>();
            foreach (string line in text.Split(new string[] { "\n", "\r\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = line.Split('=');
                responseData.Add(parts[0], parts[1]);
            }
            return responseData;
        }

        // signature
        public static string CreateSignature(string email, string password, RSAParameters key)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(key);
                var sha1 = SHA1.Create();
                byte[] prefix = { 0x00 };
                var hash = sha1.ComputeHash(GoogleKeyUtils.KeyToStruct(key)).Take(4).ToArray();
                var encrypted = rsa.Encrypt(Encoding.UTF8.GetBytes(email + "\x00" + password), true);
                return DataTypeUtils.UrlSafeBase64(DataTypeUtils.CombineBytes(prefix, hash, encrypted));
            }
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
            var rv = new byte[arrays.Sum(a => a.Length)];
            var offset = 0;
            foreach (byte[] array in arrays)
            {
                Buffer.BlockCopy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }
            return rv;
        }
    }
}