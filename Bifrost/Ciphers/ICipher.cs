using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost.Ciphers
{
    public interface ICipher
    {
        ushort CipherIdentifier { get; }
        int SecretBytes { get; }
        string HumanName { get; }

        byte[] Key { get; set; }

        byte[] Encrypt(byte[] data);
        byte[] Decrypt(byte[] data);

        void Initialize(byte[] secret);
    }
}
