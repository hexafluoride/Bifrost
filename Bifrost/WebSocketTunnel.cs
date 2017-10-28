using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Bifrost.WebSockets;
using System.Net.Sockets;
using System.Threading;
using NLog;

namespace Bifrost
{
    public class WebSocketTunnel : ITunnel
    {
        private Logger Log = LogManager.GetCurrentClassLogger();
        public WebSocketConnection Connection { get; set; }

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

        public bool Closed
        {
            get
            {
                return Connection.Closed;
            }
            set
            {

            }
        }

        public WebSocketTunnel(TcpClient client, string host, string origin, bool server)
        {
            if (server)
            {
                var conn = new ServerConnection(client);
                conn.PerformHandshake();

                Connection = conn;
            }
            else
            {
                var conn = new ClientConnection(client);
                conn.PerformHandshake(host, origin);

                Connection = conn;
            }

            Connection.StartThreads();
        }

        public void Send(byte[] data)
        {
            Connection.SendBinary(data);
            RawBytesSent += data.Length;
        }

        public byte[] Receive()
        {
            try
            {
                var msg = Connection.Receive();
                RawBytesReceived += msg.Length;

                return msg;
            }
            catch (Exception ex)
            {
                Log.Error("WebSocket connection broken, closing tunnel");
                Log.Error(ex);
                Close();

                return null;
            } 
        }

        public void Close()
        {
            Connection.Close();
        }
    }
}
