using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost.Udp
{
    public class UdpSession
    {
        public UdpClient Socket { get; set; }
        public UdpListener Listener { get; set; }
        public IPEndPoint EndPoint { get; set; }

        internal BlockingCollection<byte[]> ReceiveQueue = new BlockingCollection<byte[]>();

        public UdpSession(UdpClient socket, UdpListener listener, IPEndPoint endpoint)
        {
            Socket = socket;
            Listener = listener;
            EndPoint = endpoint;
        }

        internal void Push(byte[] data)
        {
            if (data.Length == 0)
                return;

            ReceiveQueue.Add(data);
        }

        public byte[] Receive()
        {
            var ret = ReceiveQueue.Take();
            return ret;
        }

        public void Send(byte[] data)
        {
            Socket.Send(data, data.Length, EndPoint);
        }
    }
}
