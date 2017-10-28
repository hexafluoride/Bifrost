using NLog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost.WebSockets
{
    public class WebSocketConnection
    {
        static Logger Log = LogManager.GetCurrentClassLogger();
        internal string WebsocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        public TcpClient Client { get; set; }
        public NetworkStream NetworkStream { get; set; }

        public event DataReceived OnDataReceived;

        private WebSocketMessage FragmentStart { get; set; }
        private MemoryStream FragmentBuffer = new MemoryStream();

        public bool BufferedWrite = false;

        internal bool Closed { get; set; }
        internal bool MaskOutgoing { get; set; }

        internal SizeQueue<byte[]> SendQueue = new SizeQueue<byte[]>(500);
        internal SizeQueue<byte[]> ReceiveQueue = new SizeQueue<byte[]>(500);

        public void StartThreads()
        {
            Task.Factory.StartNew(ReceiveLoop);
            Task.Factory.StartNew(SendLoop);

            //BufferedWrite = true;
        }

        private void SendLoop()
        {
            while(Client.Connected && !Closed)
            {
                try
                {
                    byte[] msg = SendQueue.Dequeue();

                    SendReal(msg);
                }
                catch (Exception ex)
                {
                    Log.Error(ex);
                    Close();
                }
            }
        }

        public byte[] Receive()
        {
            return ReceiveQueue.Dequeue();
        }

        private void ReceiveLoop()
        {
            WebSocketMessage message = new WebSocketMessage();

            while (Client.Connected && !Closed)
            {
                try
                {
                    var result = WebSocketMessage.FromStream(message, NetworkStream);
                    if(result == null)
                    {
                        Close();
                        return;
                    }

                    if (message.Final)
                    {
                        if (FragmentStart != null)
                        {
                            if (message.Opcode != Opcode.Continuation)
                            {
                                // control message
                            }
                            else
                            {
                                FragmentBuffer.Write(message.Payload, 0, message.Payload.Length);

                                if (OnDataReceived != null)
                                {
                                    OnDataReceived(this, FragmentStart, FragmentBuffer.ToArray());
                                }

                                ReceiveQueue.Enqueue(FragmentBuffer.ToArray());

                                FragmentStart = null;
                                FragmentBuffer.SetLength(0);
                            }
                        }
                        else
                        {
                            switch (message.Opcode)
                            {
                                case Opcode.Binary:
                                case Opcode.Text:
                                    ReceiveQueue.Enqueue(message.Payload);

                                    if (OnDataReceived != null)
                                        OnDataReceived(this, message, message.Payload);

                                    break;
                                case Opcode.Ping:
                                    Send(WebSocketMessage.Create(message.Payload, Opcode.Pong, MaskOutgoing));
                                    Log.Info("Received ping");
                                    break;
                                case Opcode.Pong:
                                    Log.Info("Received pong");
                                    break;
                                case Opcode.Close:
                                    Send(WebSocketMessage.Create(new byte[0], Opcode.Close, MaskOutgoing));
                                    Close();
                                    Log.Info("Received WebSocket close, disconnected");
                                    return;
                            }
                        }
                    }
                    else
                    {
                        if (FragmentStart == null)
                        {
                            // start receiving a fragment
                            FragmentStart = message;
                            FragmentBuffer.SetLength(0);
                            FragmentBuffer.Write(message.Payload, 0, message.Payload.Length);
                        }
                        else
                        {
                            if (message.Opcode != Opcode.Continuation)
                            {
                                // illegal
                            }
                            else
                            {
                                FragmentBuffer.Write(message.Payload, 0, message.Payload.Length);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Log.Error(ex);
                    Close();
                }
            }
        }

        public void Close()
        {
            try
            {
                if (BufferedWrite)
                    Send(WebSocketMessage.Create(new byte[0], Opcode.Close, MaskOutgoing));
                else
                    SendReal(WebSocketMessage.Create(new byte[0], Opcode.Close, MaskOutgoing).Serialize());
            }
            catch
            {

            }
            Closed = true;
            Client.Close();

            // unblock external Receive() calls
            ReceiveQueue.Enqueue(new byte[0]);
        }

        public void SendPing()
        {
            Send(WebSocketMessage.Create(new byte[0], Opcode.Ping, MaskOutgoing));
        }

        public void SendBinary(byte[] data)
        {
            Send(WebSocketMessage.SerializeInPlace(true, MaskOutgoing, Opcode.Binary, data, new byte[4]));
        }

        public void SendText(string data)
        {
            Send(WebSocketMessage.Create(Encoding.UTF8.GetBytes(data), Opcode.Text, MaskOutgoing));
        }

        public void Send(byte[] raw)
        {
            try
            {
                if (BufferedWrite)
                {
                    SendQueue.Enqueue(raw);
                }
                else
                {
                    SendReal(raw);
                }
            }
            catch
            {
                Close();
            }
        }

        public void Send(WebSocketMessage message)
        {
            byte[] buf = message.Serialize();
            Send(buf);
        }

        internal void SendReal(byte[] wire)
        {
            NetworkStream.Write(wire, 0, wire.Length);
            NetworkStream.Flush();
        }

        internal void WriteHeaders(Stream stream, params string[] headers)
        {
            StringBuilder sb = new StringBuilder();

            foreach (var header in headers)
                sb.AppendFormat("{0}\r\n", header);

            sb.Append("\r\n");

            byte[] buf = Encoding.ASCII.GetBytes(sb.ToString());

            stream.Write(buf, 0, buf.Length);
        }
    }
}
