using System;
using System.Security.Cryptography;
using System.Text;

namespace AWS4URLGenerator
{
    public static class AWS4URLGenerator
    {
        /// <summary>
        /// Method for building the pre-signed URL for connecting to AWS.
        /// This took a long time to figure out; the query parameters are
        /// required to be in the order that they are in and case matters!
        /// </summary>
        /// <param name="access_key"></param>
        /// <param name="secret_key"></param>
        /// <param name="protocal"></param>
        /// <param name="method"></param>
        /// <param name="endpoint"></param>
        /// <param name="region"></param>
        /// <param name="service"></param>
        /// <param name="uri"></param>
        /// <param name="svc_query">Parameters need to be in alpha order.</param>
        /// <param name="date"></param>
        /// <param name="expires"></param>
        /// <returns></returns>
        public static string GetPresignedURL(
            string access_key,
            string secret_key,
            string protocal,
            string method,
            string endpoint,
            string region,
            string service,
            string uri,
            string svc_query,
            DateTime date,
            int expires
            )
        {
            string result = "";

            string shortDate = date.ToString("yyyyMMdd");
            string amzDate = date.ToString("yyyyMMdd'T'HHmmss'Z'");

            string query = $"X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={access_key}%2F{shortDate}%2F{region}%2F{service}%2Faws4_request&X-Amz-Date={amzDate}&X-Amz-Expires={expires}&X-Amz-SignedHeaders=host&{svc_query}";

            string canonical_request = method.ToUpper() + "\n"
                + uri + "\n"
                + query + "\n"
                + $"host:{endpoint}\n"
                + "\n"
                + "host\n"
                + HexDigest(SHA256(""));

            string string_to_sign = "AWS4-HMAC-SHA256\n"
                + amzDate + "\n"
                + $"{shortDate}/{region}/{service}/aws4_request\n"
                + HexDigest(SHA256(canonical_request));

            byte[] signing_key = GetSignatureKey(secret_key, shortDate, region, service);

            string signature = HexDigest(HmacSHA256(string_to_sign, signing_key));

            query += "&X-Amz-Signature=" + signature;

            result = $"{protocal}://{endpoint}{uri}?{query}";

            return result;
        }

        /// <summary>
        /// Method for calculating SHA256 hashes
        /// </summary>
        /// <param name="x"></param>
        /// <returns></returns>
        private static byte[] SHA256(string x)
        {
            var crypt = System.Security.Cryptography.SHA256.Create();
            byte[] crypto = crypt.ComputeHash(Encoding.UTF8.GetBytes(x));

            return crypto;
        }

        /// <summary>
        /// Converts 'array' to lowercase hex.
        /// </summary>
        /// <param name="array"></param>
        /// <returns></returns>
        private static string HexDigest(byte[] array)
        {
            var hash = new StringBuilder();
            foreach (byte theByte in array)
            {
                hash.Append(theByte.ToString("x2"));
            }
            return hash.ToString();
        }

        /// <summary>
        /// Performs the Hmac keyed hash algorithm.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        private static byte[] HmacSHA256(String data, byte[] key)
        {
            String algorithm = "HmacSHA256";
            KeyedHashAlgorithm kha = KeyedHashAlgorithm.Create(algorithm);
            kha.Key = key;

            return kha.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        /// <summary>
        /// Calculates the signing key for the AWS request signature.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="dateStamp"></param>
        /// <param name="regionName"></param>
        /// <param name="serviceName"></param>
        /// <returns></returns>
        private static byte[] GetSignatureKey(String key, String dateStamp, String regionName, String serviceName)
        {
            byte[] kSecret = Encoding.UTF8.GetBytes(("AWS4" + key).ToCharArray());
            byte[] kDate = HmacSHA256(dateStamp, kSecret);
            byte[] kRegion = HmacSHA256(regionName, kDate);
            byte[] kService = HmacSHA256(serviceName, kRegion);
            byte[] kSigning = HmacSHA256("aws4_request", kService);

            return kSigning;
        }
    }
}
