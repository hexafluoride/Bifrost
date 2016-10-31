using System;
using System.Text;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;

using System.Threading;
using System.Threading.Tasks;

using NLog;

namespace Bifrost
{
    /// <summary>
    /// Tunnels Bifrost data over pseudo-HTTP. Useful for working across HTTP proxies.
    /// </summary>
    public class HttpTunnel : ITunnel
    {
        public bool ServerSide { get; set; }
        public TcpClient Connection { get; set; }

        public bool Compression { get; set; }
        public bool Base64 { get; set; }

        public bool ForceFlush = false;

        private NetworkStream NetworkStream { get; set; }
        private StreamReader StreamReader { get; set; }

        private byte[] Header;

        private DeflateStream CompressState { get; set; }

        public bool Closed { get; set; }

        private Logger Log = LogManager.GetCurrentClassLogger();

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
        /// Constructs a new HttpTunnel with the provided parameters.
        /// </summary>
        /// <param name="socket">The TcpClient to use.</param>
        /// <param name="server">true if this tunnel is server-side, false otherwise.</param>
        /// <param name="compression">Currently unused.</param>
        /// <param name="prepare">Initializes the internal streams. Set to false if the TcpClient hasn't been connected yet, and then call InitializeStreams when it's connected.</param>
        public HttpTunnel(TcpClient socket, bool server, bool compression, bool prepare = true)
        {
            if (compression)
                throw new Exception("Compression is not supported yet.");

            socket.Client.NoDelay = true;

            Connection = socket;
            ServerSide = server;
            Compression = compression;

            GenerateHeader();

            if (prepare)
                InitializeStreams();
        }

        /// <summary>
        /// Initializes the internal streams used for communication.
        /// </summary>
        public void InitializeStreams()
        {
            NetworkStream = Connection.GetStream();
            StreamReader = new StreamReader(NetworkStream);
        }

        /// <summary>
        /// Closes the HttpTunnel. This stuff is a bit tricky(yes, trickier than the rest of the project!), and hasn't been tested a lot yet, so YMMV.
        /// </summary>
        public void Close()
        {
            NetworkStream.Close();
            Connection.Close();
            Closed = true;
        }

        /// <summary>
        /// Generates and caches the header used to make our data look like HTTP requests/responses.
        /// </summary>
        private void GenerateHeader()
        {
            StringBuilder sb = new StringBuilder();

            if (ServerSide)
            {
                sb.AppendLine("HTTP/1.1 206 Partial Content");
                sb.AppendLine("Content-Type: text/html");
                sb.AppendLine("Server: nginx");
                sb.AppendLine("Connection: keep-alive");
            }
            else
            {         
                sb.AppendLine("GET / HTTP/1.1");
                sb.AppendLine("Host: proxy.example.com");
                sb.AppendLine("User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; FSL 7.0.7.01001)"); // act like Chrome 49 running on Windows 7
            }

            Header = Encoding.UTF8.GetBytes(sb.ToString());
        }

        /// <summary>
        /// Receives a single data chunk.
        /// </summary>
        /// <returns>The received chunk of data.</returns>
        public byte[] Receive()
        {
            try
            {
                if (!Connection.Connected)
                {
                    Close();
                    return null;
                }

                string line = NetworkStream.ReadLine();

                int counter = 0;
                while (!line.StartsWith("Content-Length: "))
                {
                    counter++;
                    line = NetworkStream.ReadLine();
                    RawBytesReceived += line.Length;

                    if (counter > 15)
                    {
                        Log.Warn("Recovering from desynchronized stream...");
                        return new byte[0];
                    }
                }

                int length = int.Parse(line.Split(':')[1].Trim());

                //StreamReader.ReadLine();
                NetworkStream.ReadByte();
                RawBytesReceived++;

                byte[] buf = new byte[length];
                int index = 0;

                counter = 0;

                while (index < length)
                {
                    try
                    {
                        int read = NetworkStream.Read(buf, index, length - index);
                        index += read;

                        counter++;

                        if (counter > 20)
                        {
                            Log.Warn("Recovering from desynchronized stream...");
                            return new byte[0];
                        }
                    }
                    catch (IOException ex)
                    {
                        Log.Error("Read timeout({0})", ex.Message);
                        return new byte[0];
                    }
                }

                RawBytesReceived += length;
                //DataBytesReceived += length;

                return buf;
            }
            catch (Exception ex)
            {
                Log.Error("HttpTunnel broken, closing({0}).", ex.Message);
                Close();
                return null;
            }
        }

        /// <summary>
        /// Wraps raw data inside HTTP headers to prepare it for sending.
        /// </summary>
        /// <param name="data">The data to wrap.</param>
        /// <returns>The wrapped data.</returns>
        public byte[] WrapData(byte[] data)
        {
            MemoryStream ms = new MemoryStream();

            StringBuilder sb = new StringBuilder();

            if (Base64)
            {
                data = Encoding.UTF8.GetBytes(Convert.ToBase64String(data));
            }

            sb.AppendFormat("Content-Length: {0}\n", data.Length);

            sb.AppendLine();

            byte[] header_dyn = Encoding.UTF8.GetBytes(sb.ToString());

            ms.Write(Header, 0, Header.Length);
            ms.Write(header_dyn, 0, header_dyn.Length);
            ms.Write(data, 0, data.Length);

            byte[] ret = ms.ToArray();

            ms.Close();

            return ret;
        }

        /// <summary>
        /// Sends a data chunk over the HttpTunnel. To-be-shim?
        /// </summary>
        /// <param name="data">The data to be sent.</param>
        public void Send(byte[] data)
        {
            SendRaw(data);
        }

        /// <summary>
        /// Wraps and sends raw data over the HttpTunnel.
        /// </summary>
        /// <param name="data">The data to be sent.</param>
        public void SendRaw(byte[] data)
        {
            byte[] wrapped_data = WrapData(data);

            lock (NetworkStream)
            {
                if (!NetworkStream.CanWrite || Closed)
                    return;

                NetworkStream.Write(wrapped_data, 0, wrapped_data.Length);
                NetworkStream.Flush();
            }

            //DataBytesSent += data.Length;
            RawBytesSent += wrapped_data.Length;
        }
    }
}