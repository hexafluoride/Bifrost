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
        private BlockingCollection<UdpSession> NewSessions = new BlockingCollection<UdpSession>();
        public int Port { get; set; }

        public bool Running { get; set; }
        public bool QueueConnections { get; set; }
        private Thread listener_thread;
        private ManualResetEvent listener_stop = new ManualResetEvent(false);

        public Dictionary<byte[], UdpSession> Sessions = new Dictionary<byte[], UdpSession>(new StructuralEqualityComparer<byte[]>());

        public UdpListener(IPAddress listen, int port, bool queue = true)
        {
            Running = false;
            QueueConnections = queue;

            Socket = new UdpClient(new IPEndPoint(listen, port));
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
        }

        public ITunnel Accept()
        {
            return new UdpTunnel(NewSessions.Take());
        }

        public void Close(IPEndPoint endpoint)
        {
            Sessions.Remove(EndPointToTuple(endpoint));
        }

        public void Close(UdpSession session)
        {
            Sessions.Remove(EndPointToTuple(session.EndPoint));
        }

        public void HandlePackets()
        {
            IPEndPoint receive_ep = new IPEndPoint(IPAddress.Any, 0);

            while(!listener_stop.WaitOne(0))
            {
                byte[] buf = Socket.Receive(ref receive_ep);

                //Log.Info(buf.Length);

                try
                {
                    byte[] tuple = EndPointToTuple(receive_ep);

                    if (Sessions.ContainsKey(tuple))
                    {
                        Sessions[tuple].Push(buf);
                    }
                    else
                    {
                        UdpSession session = new UdpSession(Socket, this, receive_ep);

                        Sessions.Add(tuple, session);

                        if (QueueConnections)
                        {
                            NewSessions.Add(session);
                        }

                        if (buf.Length > 0)
                            session.Push(buf);
                        else
                            session.Send(new byte[0]);
                    }
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
