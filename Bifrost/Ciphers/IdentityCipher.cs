using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost.Ciphers
{
    public class IdentityCipher : ICipher
    {
        public const ushort Identifier = 0;

        public ushort CipherIdentifier { get { return Identifier; } }
        public int SecretBytes { get { return 0; } }
        public string HumanName { get { return "Identity(no encryption)"; } }

        public byte[] Key { get; set; }

        public IdentityCipher()
        {

        }

        public byte[] Encrypt(byte[] data)
        {
            return data;
        }

        public byte[] Decrypt(byte[] data)
        {
            return data;
        }

        public void Initialize(byte[] secret)
        {

        }
    }
}
