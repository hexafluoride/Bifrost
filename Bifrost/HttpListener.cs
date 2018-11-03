using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost
{
    public class HttpListener : IListener
    {
        public BlockingCollection<ITunnel> Queue { get; set; }

        public TcpListener Listener { get; set; }

        public bool Server { get; set; }
        public bool Compression { get; set; }

        public ITunnel Accept()
        {
            return new HttpTunnel(Listener.AcceptTcpClient(), Server, Compression);
        }

        public void Start()
        {
            Listener.Start();
        }

        public void Stop()
        {
            Listener.Stop();
        }
    }
}
