using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost.MACs
{
    public class HMACSHA : IMAC
    {
        public const ushort Identifier = 1;
        public ushort MACIdentifier => Identifier;

        public int SecretBytes => 64;
        public string HumanName => "HMAC-SHA256";
        public int OutputLength => 32;

        private byte[] _secret;

        public HMACSHA()
        {

        }

        public void Initialize(byte[] secret)
        {
            _secret = secret;
        }

        public byte[] Calculate(byte[] message)
        {
            var hmac = new HMACSHA256(_secret);
            return hmac.ComputeHash(message);
        }
    }
}
