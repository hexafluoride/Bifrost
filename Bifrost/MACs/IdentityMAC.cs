using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost.MACs
{
    public class IdentityMAC : IMAC
    {
        public const ushort Identifier = 0;

        public ushort MACIdentifier => Identifier;
        public string HumanName => "identity MAC";
        public int SecretBytes => 0;
        public int OutputLength => 0;

        public byte[] Calculate(byte[] message)
        {
            return new byte[0];
        }

        public void Initialize(byte[] secret)
        {
        }
    }
}
