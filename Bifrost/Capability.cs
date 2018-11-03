using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost
{
    enum Capability
    {
        CapabilityNegotiation = 0x00,
        Heartbeat = 0x01,
        CipherSelection = 0x02
    }
}
