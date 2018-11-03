using NLog;
using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Bifrost.Udp
{
    public class UdpListener : IListener
    {
        public Logger Log = LogManager.GetCurrentClassLogger();

        public UdpClient Socket { get; set; }
        public BlockingCollection<ITunnel> Queue { get; set; }
        public IPEndPoint EndPoint { get; set; }
        public int Port { get; set; }

        public bool Running { get; set; }
        public bool QueueConnections { get; set; }
        private Thread listener_thread;
        private ManualResetEvent listener_stop = new ManualResetEvent(false);

        internal Dictionary<byte[], UdpSession> Sessions = new Dictionary<byte[], UdpSession>(new StructuralEqualityComparer<byte[]>());

        public UdpListener(IPAddress listen, int port, bool queue = true)
        {
            Queue = new BlockingCollection<ITunnel>();

            Running = false;
            QueueConnections = queue;

            EndPoint = new IPEndPoint(listen, port);
            Port = port;

            //Task.Factory.StartNew(HandlePackets);
        }

        public UdpListener(IPEndPoint ep) :
            this(ep.Address, ep.Port)
        {

        }

        public void Start()
        {
            if (Running)
                return;
            
            Socket = new UdpClient(EndPoint);
            Socket.DontFragment = false;

            listener_stop.Reset();

            listener_thread = new Thread(new ThreadStart(HandlePackets));
            listener_thread.Start();

            Running = true;
        }

        public void Stop()
        {
            if (!Running)
                return;

            listener_stop.Set();
            Thread.Sleep(100);

            listener_thread.Abort();

            Running = false;

            Socket.Close();
        }

        public ITunnel Accept()
        {
            return Queue.Take();
        }

        public void Close(IPEndPoint endpoint)
        {
            Sessions.Remove(EndPointToTuple(endpoint));
        }

        internal void Close(UdpSession session)
        {
            Sessions.Remove(EndPointToTuple(session.EndPoint));
        }

        public void HandlePackets()
        {
            IPEndPoint receive_ep = new IPEndPoint(IPAddress.Any, 0);
            var mtu_special = Encoding.ASCII.GetBytes("MTU ");

            while (!listener_stop.WaitOne(0))
            {
                try
                {
                    byte[] buf = Socket.Receive(ref receive_ep);
                    byte[] tuple = EndPointToTuple(receive_ep);

                    if (Sessions.ContainsKey(tuple))
                    {
                        var session = Sessions[tuple];

                        bool mtu_probe = true;

                        for(int i = 0; i < 4; i++)
                        {
                            if (buf[i] != mtu_special[i])
                            {
                                mtu_probe = false;
                                break;
                            }
                        }

                        if (mtu_probe)
                        {
                            session.GoodMTUs.Add(buf.Length);
                            session.LastMTUProbe = DateTime.Now;
                            continue;
                        }

                        if(session.L7FragmentationCapable && !session.NegotiatingMTU)
                        {
                            session.HandleFragment(buf);
                        }
                        else
                        {
                            session.Push(buf);
                        }
                    }
                    else
                    {
                        var session = new UdpSession(Socket, this, receive_ep);

                        Message syn_msg = null;

                        try
                        {
                            syn_msg = Message.Parse(buf);
                        }
                        catch (Exception ex)
                        {
                            Log.Info("Ignored improper connection attempt with message {0}/0x{1:X2}", syn_msg?.Type, syn_msg?.Subtype);
                            continue;
                        }

                        if (syn_msg == null || syn_msg.Type != MessageType.Control || syn_msg.Subtype != UdpSession.SYN)
                        {
                            Log.Info("Ignored improper connection attempt with message {0}/0x{1:X2}", syn_msg?.Type, syn_msg?.Subtype);
                            continue;
                        }

                        Sessions[tuple] = session;

                        Utilities.StartThread(delegate
                        {
                            var syn_ack_msg = new Message(MessageType.Control, UdpSession.SYN_ACK);
                            syn_ack_msg.Store["capabilities"] = new byte[] { (byte)UdpCapabilities.L7Fragmentation };

                            session.Send(syn_ack_msg.Serialize());

                            var ack_msg = session.ReceiveMessage(UdpSession.HANDSHAKE_TIMEOUT);

                            if (ack_msg == null || ack_msg.Type != MessageType.Control || ack_msg.Subtype != UdpSession.ACK)
                            {
                                Log.Info("Ignored improper connection attempt with message {0}/0x{1:X2}", ack_msg?.Type, ack_msg?.Subtype);
                                Sessions.Remove(tuple);
                                return;
                            }

                            if(ack_msg.Store.ContainsKey("capabilities"))
                            {
                                session.L7FragmentationCapable = ack_msg.Store["capabilities"].Contains((byte)UdpCapabilities.L7Fragmentation);
                            }

                            Log.Info("Accepted UDP connection on {0}{1}", receive_ep, QueueConnections ? ", queueing session" : "");
                            
                            if (session.L7FragmentationCapable)
                            {
                                Log.Info("Negotiating MTU...");
                                session.NegotiateMTU();
                            }

                            if (QueueConnections)
                                Queue.Add(new UdpTunnel(session));
                        });
                    }
                }
                catch (SocketException ex)
                {
                    Log.Error(ex);
                }
                catch (Exception ex)
                {
                    Log.Error(ex);
                }
            }
        }

        public static byte[] EndPointToTuple(IPEndPoint ep)
        {
            byte[] tuple = new byte[6];

            Array.Copy(ep.Address.GetAddressBytes(), tuple, 4);
            Array.Copy(BitConverter.GetBytes((ushort)ep.Port), 0, tuple, 4, 2);

            return tuple;
        }

        public override string ToString()
        {
            return ((IPEndPoint)Socket.Client.LocalEndPoint).ToString();
        }
    }

    enum UdpCapabilities
    {
        L7Fragmentation = 0x01
    }

    public class StructuralEqualityComparer<T> : IEqualityComparer<T>
    {
        public bool Equals(T x, T y)
        {
            return StructuralComparisons.StructuralEqualityComparer.Equals(x, y);
        }

        public int GetHashCode(T obj)
        {
            return StructuralComparisons.StructuralEqualityComparer.GetHashCode(obj);
        }

        private static StructuralEqualityComparer<T> defaultComparer;
        public static StructuralEqualityComparer<T> Default
        {
            get
            {
                StructuralEqualityComparer<T> comparer = defaultComparer;
                if (comparer == null)
                {
                    comparer = new StructuralEqualityComparer<T>();
                    defaultComparer = comparer;
                }
                return comparer;
            }
        }
    }
}
