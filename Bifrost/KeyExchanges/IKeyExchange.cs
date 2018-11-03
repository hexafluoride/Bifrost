using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost.KeyExchanges
{
    public interface IKeyExchange
    {
        ushort KeyExchangeIdentifier { get; }
        string HumanName { get; }

        byte[] GetPublicKey();

        byte[] FinalizeKeyExchange(byte[] peer_pk);
        void Initialize();
    }
}
