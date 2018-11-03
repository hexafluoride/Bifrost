using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost.Ciphers
{
    public class AesCbcCipher : ICipher
    {
        public const ushort Identifier = 1;

        public ushort CipherIdentifier { get { return Identifier; } }
        public int SecretBytes { get { return 16; } }
        public string HumanName { get { return "AES-CBC"; } }

        private byte[] raw_key;
        private KeyParameter _key;

        public byte[] Key { get { return raw_key; } set { raw_key = value; _key = new KeyParameter(raw_key); } }

        public RNGCryptoServiceProvider RNG = new RNGCryptoServiceProvider();

        public AesCbcCipher()
        {

        }

        public byte[] Encrypt(byte[] data)
        {
            AesManaged aes = new AesManaged();

            aes.KeySize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            MemoryStream ms = new MemoryStream();
            
            ms.Write(aes.IV, 0, 16);
            
            aes.Key = raw_key;
            var encryptor = aes.CreateEncryptor();

            var stream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
            stream.Write(data, 0, data.Length);
            stream.FlushFinalBlock();

            return ms.ToArray();
        }

        public byte[] Decrypt(byte[] data)
        {
            AesManaged aes = new AesManaged();

            aes.KeySize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            MemoryStream ms = new MemoryStream(data);
            ms.Position = 16;

            byte[] iv = new byte[16];
            Array.Copy(data, iv, 16);
            aes.IV = iv;
            
            aes.Key = raw_key;
            var decryptor = aes.CreateDecryptor();

            CryptoStream stream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);

            byte[] ret = new byte[data.Length - 16];

            while(stream.Read(ret, 0, ret.Length) != 0)
            {
            }

            return ret;
            //return stream.ReadToEnd();
        }

        public void Initialize(byte[] secret)
        {
            Key = secret;
        }
    }
}
