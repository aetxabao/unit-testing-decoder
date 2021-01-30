using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Serialization;

namespace CryptoLib
{
    public class X
    {

        public static string RsaGetPubParsXml(RSACryptoServiceProvider rsa)
        {
            bool isPriv = false;
            RSAParameters pars = new RSAParameters();
            pars.Exponent = rsa.ExportParameters(isPriv).Exponent;
            pars.Modulus = rsa.ExportParameters(isPriv).Modulus;
            return RsaParsToXml(pars);
        }
        private static string RsaParsToXml(RSAParameters pars)
        {
            var serializer = new XmlSerializer(typeof(RSAParameters));
            var settings = new XmlWriterSettings
            {
                Encoding = new UTF8Encoding(true),
                Indent = false,
                NewLineHandling = NewLineHandling.None
            };
            using (var stringWriter = new Utf8StringWriter())
            {
                using (var xmlWriter = XmlWriter.Create(stringWriter, settings))
                {
                    serializer.Serialize(xmlWriter, pars);
                }
                return stringWriter.ToString();
            }
        }
        private static RSAParameters RsaParsFromXml(string data) 
        {
            return new RSAParameters();
        }

        public static string RsaEncrypt(string text, string pubParsXml)
        {
            return null;
        }

        public static string RsaDecrypt(string code, RSACryptoServiceProvider rsa)
        {
            return null;
        }
        public static string SignedData(string text, RSACryptoServiceProvider rsa)
        {
            return null;
        }
        public static bool VerifyData(string text, string signedText, string pubParsXml)
        {
            return false;
        }


        public static string AesEncrypt(string msg, string pwd, out string iv)
        {
            iv = "";
            return null;
        }
        public static string AesDecrypt(string enc, string pwd, string sal)
        {
            return null;
        }

        public static string ShaHash(Object input)
        {
            return null;
        }

        public static string RandomString(int length)
        {
            const string valid = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            StringBuilder res = new StringBuilder();
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] uintBuffer = new byte[sizeof(uint)];

                while (length-- > 0)
                {
                    rng.GetBytes(uintBuffer);
                    uint num = BitConverter.ToUInt32(uintBuffer, 0);
                    res.Append(valid[(int)(num % (uint)valid.Length)]);
                }
            }
            return res.ToString();
        }

    }

    public class Utf8StringWriter : StringWriter
    {
        public override Encoding Encoding => Encoding.UTF8;

    }
}
