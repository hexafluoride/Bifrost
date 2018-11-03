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
        internal UdpSession Session { get; set; }
        private IPEndPoint EndPoint { get; set; }

        private Logger Log = LogManager.GetCurrentClassLogger();

        public static int SourcePortStart = 10100;
        public static int SourcePortEnd = 20200;

        private static int SourcePort = 10100;

        #region Statistics
        public ulong PacketsDropped { get => Session.DroppedFragments; }
        public ulong PacketsReceived { get => Session.ReceivedFragments; }
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

        internal UdpTunnel(UdpSession session)
        {
            Session = session;
        }

        public UdpTunnel(IPAddress addr, int port, int mtu = 0)
        {
            SourcePort++;

            if (SourcePort > SourcePortEnd)
                SourcePort = SourcePortStart;

            EndPoint = new IPEndPoint(addr, port);

            UdpListener temp_listener = new UdpListener(IPAddress.Any, SourcePort, false);
            temp_listener.Start();

            Session = new UdpSession(temp_listener.Socket, temp_listener, EndPoint);
            Session.ForceMTU = mtu;
            temp_listener.Sessions[UdpListener.EndPointToTuple(EndPoint)] = Session;

            Session.Connect();
        }

        public UdpTunnel(IPEndPoint ep, int mtu = 0) :
            this(ep.Address, ep.Port, mtu)
        {

        }

        public void Close()
        {
            Closed = true;
            Session.ReceiveQueue.Add(new byte[0]); // unblock Receive()

            if (!Session.Listener.QueueConnections)
                Session.Listener.Stop();

            Session.Listener.Close(Session);
        }

        public void Send(byte[] data)
        {
            RawBytesSent += data.Length;
            Session.Send(data);
        }

        public byte[] Receive()
        {
            var ret = Session.Receive();
            RawBytesReceived += ret.Length;
            
            return ret;
        }

        public override string ToString()
        {
            return string.Format("UDP tunnel on {0}", EndPoint);
        }
    }
}
