using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost
{
    public class WebSocketListener : IListener
    {
        public TcpListener Listener { get; set; }

        public bool Server { get; set; }
        public string Host { get; set; }
        public string Origin { get; set; }

        public ITunnel Accept()
        {
            return new WebSocketTunnel(Listener.AcceptTcpClient(), Host, Origin, Server);
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
