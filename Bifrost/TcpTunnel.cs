using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost
{
    /// <summary>
    /// Tunnels Bifrost data over very simple TCP. 4 bytes of overhead per message.
    /// </summary>
    public class TcpTunnel : ITunnel
    {
        public TcpClient Connection { get; set; }
        public NetworkStream NetworkStream { get; set; }

        public bool Closed { get; set; }

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

        /// <summary>
        /// Construct a new TcpTunnel with the provided parameters.
        /// </summary>
        /// <param name="client">The TcpClient to use.</param>
        /// <param name="prepare">Initializes the internal streams. Set to false if the TcpClient hasn't been connected yet, and then call InitializeStreams when it's connected.</param>
        public TcpTunnel(TcpClient client, bool prepare = true)
        {
            Connection = client;

            if (prepare)
                InitializeStreams();
        }

        /// <summary>
        /// Initializes the internal streams used for communication.
        /// </summary>
        public void InitializeStreams()
        {
            NetworkStream = Connection.GetStream();
        }

        /// <summary>
        /// Closes the TcpTunnel. This stuff is a bit tricky(yes, trickier than the rest of the project!), and hasn't been tested a lot yet, so YMMV.
        /// </summary>
        public void Close()
        {
            Connection.Close();
            Closed = true;
        }

        /// <summary>
        /// Receives a single data chunk.
        /// </summary>
        /// <returns>The received chunk of data.</returns>
        public byte[] Receive()
        {
            uint len = NetworkStream.ReadUInt();

            RawBytesReceived += len + 4;
            DataBytesReceived += len;

            return NetworkStream.ReadSafe(len);
        }

        /// <summary>
        /// Sends raw data over the TcpTunnel.
        /// </summary>
        /// <param name="data">The data to be sent.</param>
        public void Send(byte[] data)
        {
            NetworkStream.WriteUInt((uint)data.Length);
            NetworkStream.Write(data, 0, data.Length);

            RawBytesSent += data.Length + 4;
            DataBytesSent += data.Length;
        }
    }
}
