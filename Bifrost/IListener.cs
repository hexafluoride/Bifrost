using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost
{
    public interface IListener
    {
        BlockingCollection<ITunnel> Queue { get; set; }

        ITunnel Accept();

        void Start();
        void Stop(); 
    }
}
