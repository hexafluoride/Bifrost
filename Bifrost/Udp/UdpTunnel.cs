using NLog;
using System.Net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost.Udp
{
    public class UdpTunnel : ITunnel
    {
        public bool Closed { get; set; }
        public UdpSession Session { get; set; }
        private IPEndPoint EndPoint { get; set; }

        private Logger Log = LogManager.GetCurrentClassLogger();

        public static int SourcePortStart = 10100;
        public static int SourcePortEnd = 20200;

        private static int SourcePort = 10100;

        #region Statistics
        public long RawBytesSent { get; set; }
        public long DataBytesSent { get; set; }
        public long ProtocolBytesSent
        {
            get
            {
                return RawBytesSent - DataBytesSent;
            }
        }
        public double OverheadSent
        {
            get
            {
                return (double)ProtocolBytesSent / (double)RawBytesSent;
            }
        }

        public long RawBytesReceived { get; set; }
        public long DataBytesReceived { get; set; }
        public long ProtocolBytesReceived
        {
            get
            {
                return RawBytesReceived - DataBytesReceived;
            }
        }
        public double OverheadReceived
        {
            get
            {
                return (double)ProtocolBytesReceived / (double)RawBytesReceived;
            }
        }
        #endregion

        public UdpTunnel(UdpSession session)
        {
            Session = session;
        }

        public UdpTunnel(IPAddress addr, int port)
        {
            SourcePort++;

            if (SourcePort > SourcePortEnd)
                SourcePort = SourcePortStart;

            EndPoint = new IPEndPoint(addr, port);

            UdpListener temp_listener = new UdpListener(IPAddress.Any, SourcePort);
            temp_listener.Socket.Send(new byte[0], 0, EndPoint);

            temp_listener.Start();

            Session = new UdpSession(temp_listener.Socket, temp_listener, EndPoint);
        }

        public UdpTunnel(IPEndPoint ep) :
            this(ep.Address, ep.Port)
        {

        }

        public void Close()
        {
            Session.Listener.Close(Session);
        }

        public void Send(byte[] data)
        {
            Session.Send(data);
        }

        public byte[] Receive()
        {
            return Session.Receive();
        }
    }
}
