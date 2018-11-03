using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost.Ciphers
{
    public class ChaChaCipher : ICipher
    {
        public const ushort Identifier = 3;

        public ushort CipherIdentifier { get { return Identifier; } }
        public int SecretBytes { get { return 32; } }
        public string HumanName { get { return "ChaCha20"; } }

        private byte[] raw_key;
        private KeyParameter _key;

        public byte[] Key { get { return raw_key; } set { raw_key = value; _key = new KeyParameter(raw_key); } }

        public ChaChaCipher()
        {

        }

        public byte[] Encrypt(byte[] data)
        {
            ChaChaEngine chacha = new ChaChaEngine();

            byte[] iv = new byte[8];
            
            chacha.Init(true, new ParametersWithIV(_key, iv));

            byte[] output = new byte[data.Length + iv.Length];

            Array.Copy(iv, output, iv.Length);
            chacha.ProcessBytes(data, 0, data.Length, output, iv.Length);

            return output;
        }

        public byte[] Decrypt(byte[] data)
        {
            ChaChaEngine chacha = new ChaChaEngine();

            byte[] iv = new byte[8];
            Array.Copy(data, iv, iv.Length);

            chacha.Init(true, new ParametersWithIV(_key, iv));

            byte[] output = new byte[data.Length - iv.Length];

            chacha.ProcessBytes(data, iv.Length, data.Length - iv.Length, output, 0);

            return output;
        }

        public void Initialize(byte[] secret)
        {
            Key = secret;
        }
    }
}
