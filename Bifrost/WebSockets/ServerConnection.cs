using NLog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost.WebSockets
{
    public delegate void DataReceived(object sender, WebSocketMessage message, byte[] payload);
    public class ServerConnection : WebSocketConnection
    {
        static Logger Log = LogManager.GetCurrentClassLogger();

        public ServerConnection(TcpClient client)
        {
            Client = client;
            NetworkStream = Client.GetStream();
        }

        public void PerformHandshake()
        {
            List<string> lines = new List<string>();
            string line = "";

            do
            {
                line = NetworkStream.ReadLine();
                lines.Add(line);
            }
            while (!string.IsNullOrWhiteSpace(line));

            foreach (var str in lines)
                Log.Trace("HTTP header: \"{0}\"", str);

            Dictionary<string, string> headers =
                lines.Select(l =>
                    new KeyValuePair<string, string>(
                        l.Split(':')[0],
                        string.Join(":", l.Split(':').Skip(1)).Trim()
                    )).ToDictionary(x => x.Key, x => x.Value);

            if (!headers.ContainsKey("Sec-WebSocket-Key"))
            {
                Log.Error("Request lacks WebSocket key!");

                foreach (var str in lines)
                    Log.Warn("Raw HTTP header: \"{0}\"", str);
                
                foreach (var header in headers)
                    Log.Warn("Parsed HTTP header: \"{0}: {1}\"", header.Key, header.Value);

                Close();

                return;
            }

            string key = headers["Sec-WebSocket-Key"];

            Log.Debug("WebSocket key is {0}", key);

            SHA1CryptoServiceProvider sha = new SHA1CryptoServiceProvider();
            string hash = Convert.ToBase64String(sha.ComputeHash(Encoding.ASCII.GetBytes(key + WebsocketGuid)));

            Log.Debug("WebSocket hash is {0}", hash);

            WriteHeaders(NetworkStream,
                "HTTP/1.1 101 Switching Protocols",
                "Upgrade: websocket",
                "Connection: Upgrade",
                "Sec-WebSocket-Accept: " + hash);

            Log.Info("Wrote WebSocket response");
        }
    }
}
