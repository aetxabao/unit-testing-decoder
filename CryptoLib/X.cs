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
            XmlSerializer xml = new XmlSerializer(typeof(RSAParameters));

            using (TextReader reader = new StringReader(data))
            {
                return (RSAParameters)xml.Deserialize(reader);
            }
        }


        public static string RsaEncrypt(string text, string pubParsXml)
        {
            using (RSACryptoServiceProvider tester = new RSACryptoServiceProvider())
            {
                tester.ImportParameters(RsaParsFromXml(pubParsXml));

                return
                    Convert.ToBase64String(
                        tester.Encrypt(
                            Encoding.Default.GetBytes(text),
                            false));
            }
        }


        public static string RsaDecrypt(string code, RSACryptoServiceProvider rsa)
        {
            return
                Encoding.UTF8.GetString(
                    rsa.Decrypt(
                        System.Convert.FromBase64String(code),
                        false));
        }


        public static string SignedData(string text, RSACryptoServiceProvider rsa)
        {
            return 
                Convert.ToBase64String(
                    rsa.SignData(
                        Encoding.Default.GetBytes(text),
                        new SHA1CryptoServiceProvider()));
        }


        public static bool VerifyData(string text, string signedText, string pubParsXml)
        {
            RSACryptoServiceProvider tester = new RSACryptoServiceProvider();

            tester.ImportParameters(RsaParsFromXml(pubParsXml));

            return
                tester.VerifyData(
                    Encoding.Default.GetBytes(text),
                    new SHA1CryptoServiceProvider(),
                    Convert.FromBase64String(signedText));
        }


        public static string AesEncrypt(string msg, string pwd, out string iv)
        {
            if (msg == null || msg.Length <= 0)
                throw new ArgumentNullException("msg");
            if (pwd == null || pwd.Length <= 0)
                throw new ArgumentNullException("pwd");

            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(pwd);
                iv = Convert.ToBase64String(aesAlg.IV);

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(msg);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(encrypted);
        }


        public static string AesDecrypt(string enc, string pwd, string sal)
        {
            if (enc == null || enc.Length <= 0)
                throw new ArgumentNullException("enc");
            if (pwd == null || pwd.Length <= 0)
                throw new ArgumentNullException("pwd");
            if (sal == null || sal.Length <= 0)
                throw new ArgumentNullException("sal");

            string decrypted = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(pwd);
                aesAlg.IV = System.Convert.FromBase64String(sal);

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(System.Convert.FromBase64String(enc)))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            decrypted = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return decrypted;
        }


        public static string ShaHash(Object input)
        {
            byte[] data = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes((String)input));

            StringBuilder sBuilder = new StringBuilder();

            foreach (byte b in data)
            {
                sBuilder.Append(b.ToString("x2"));
            }

            return sBuilder.ToString();
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
