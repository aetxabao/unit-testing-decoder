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
            byte[] data = Encoding.Default.GetBytes(text);
            using (RSACryptoServiceProvider tester = new RSACryptoServiceProvider())
            {
                tester.ImportParameters(pubParsXml);
                byte[] encrypted = tester.Encrypt(data, false);
                string resultado = Convert.ToBase64String(encrypted, 0, encrypted.Length);
                return resultado;
            }
        }

        public static string RsaDecrypt(string code, RSACryptoServiceProvider rsa)
        {
            byte[] encrypted = System.Convert.FromBase64String(code);
            byte[] decrypted = rsa.Decrypt(encrypted, false);
            string text = Encoding.UTF8.GetString(decrypted);
            return text;
        }
        public static string SignedData(string text, RSACryptoServiceProvider rsa)
        {
            byte[] data = Encoding.Default.GetBytes(text);
            byte[] xdata = rsa.SignData(data, new SHA1CryptoServiceProvider());
            string base64 = Convert.ToBase64String(xdata, 0, xdata.Length);
            return base64;
        }
        public static bool VerifyData(string text, string signedText, string pubParsXml)
        {
            byte[] data = Encoding.Default.GetBytes(text);
            byte[] signedData = Convert.FromBase64String(signedText);
            RSACryptoServiceProvider tester = new RSACryptoServiceProvider();
            tester.ImportParameters(pubParsXml);
            return tester.VerifyData(data, new SHA1CryptoServiceProvider(), signedData);
        }


        public static string AesEncrypt(string msg, string pwd, out string iv)
        {
            // Check arguments.
            if (msg == null || msg.Length <= 0)
                throw new ArgumentNullException("msg");
            if (pwd == null || pwd.Length <= 0)
                throw new ArgumentNullException("pwd");
            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException("iv");
            string encrypted = null;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = pwd;
                aesAlg.IV = iv;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.pwd, aesAlg.iv);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(msg);
                        }
                        encrypted = msEncrypt.toString();
                    }
                }
            }
            return encrypted;
        }

        public static string AesDecrypt(string enc, string pwd, string sal)
        {
            // Check arguments.
            if (enc == null || enc.Length <= 0)
                throw new ArgumentNullException("enc");
            if (pwd == null || pwd.Length <= 0)
                throw new ArgumentNullException("pwd");
            if (sal == null || sal.Length <= 0)
                throw new ArgumentNullException("sal");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = pwd;
                aesAlg.IV = sal;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.pwd, aesAlg.sal);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(enc))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;
        }

        public static string ShaHash(Object input)
        {
            string source = input;
            using (SHA256 sha256Hash = SHA256.Create())
            {
                string hash = GetHash(sha256Hash, source);

                Console.WriteLine($"The SHA256 hash of {source} is: {hash}.");
            }
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
