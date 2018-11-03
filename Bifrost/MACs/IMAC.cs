using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost.MACs
{
    public interface IMAC
    {
        ushort MACIdentifier { get; }
        string HumanName { get; }
        int SecretBytes { get; }
        int OutputLength { get; }

        void Initialize(byte[] secret);

        byte[] Calculate(byte[] message);
    }
}
