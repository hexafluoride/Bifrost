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
    public class ClientConnection : WebSocketConnection
    {
        static Logger Log = LogManager.GetCurrentClassLogger();

        private RNGCryptoServiceProvider RNG = new RNGCryptoServiceProvider();

        public ClientConnection(TcpClient client)
        {
            Client = client;
            NetworkStream = Client.GetStream();

            MaskOutgoing = true;
        }

        public void PerformHandshake(string host, string origin)
        {
            byte[] key = new byte[16];
            RNG.GetBytes(key);

            string str_key = Convert.ToBase64String(key);

            WriteHeaders(NetworkStream,
                "GET / HTTP/1.1",
                "Host: " + host,
                "Upgrade: websocket",
                "Connection: Upgrade",
                "Sec-WebSocket-Version: 13",
                "Origin: " + origin,
                "Sec-WebSocket-Key: " + str_key);

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
                    )).GroupBy(x => x.Key, (x, ys) => ys.First()).ToDictionary(x => x.Key, x => x.Value);

            if (!headers.ContainsKey("Sec-WebSocket-Accept"))
            {
                Log.Error("Request lacks WebSocket hash!");
                return;
            }

            string hash = headers["Sec-WebSocket-Accept"];

            Log.Debug("WebSocket hash is {0}", hash);

            SHA1CryptoServiceProvider sha = new SHA1CryptoServiceProvider();
            string expected_hash = Convert.ToBase64String(sha.ComputeHash(Encoding.ASCII.GetBytes(str_key + WebsocketGuid)));

            Log.Debug("Expected WebSocket hash is {0}", expected_hash);

            if(expected_hash != hash)
            {
                Log.Error("Hash mismatch!");
                return;
            }
        }
    }
}
