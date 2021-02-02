﻿using System;
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
            { }
            return "hola";
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
            byte[] encrypted;
            using (Aes aesAlg = Aes.Create())
            {
                byte[] key = Encoding.UTF8.GetBytes(pwd);
                Array.Resize(ref key, 32);
                aesAlg.Key = key;

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
                iv = Convert.ToBase64String(aesAlg.IV, 0, aesAlg.IV.Length);
            }
            return Convert.ToBase64String(encrypted, 0, encrypted.Length);
        }
        public static string AesDecrypt(string enc, string pwd, string sal)
        {
            byte[] encrypted = System.Convert.FromBase64String(enc);

            byte[] key = Encoding.UTF8.GetBytes(pwd);
            Array.Resize(ref key, 32);
            byte[] iv = System.Convert.FromBase64String(sal);
            Array.Resize(ref iv, 16);

            string plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(encrypted))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }

        public static string ShaHash(Object input)
        {
            var sBuilder = new StringBuilder();
            using (SHA256 hashAlgorithm = SHA256.Create())
            {
                byte[] data = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes((String)input));

                for (int i = 0; i < data.Length; i++)
                {
                    sBuilder.Append(data[i].ToString("x2"));
                }
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
