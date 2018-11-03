using NLog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Bifrost
{
    public class WebSocketListener : IListener
    {
        private Logger Log = LogManager.GetCurrentClassLogger();

        public TcpListener Listener { get; set; }

        public bool Server { get; set; }
        public string Host { get; set; }
        public string Origin { get; set; }

        public BlockingCollection<ITunnel> Queue { get; set; }

        private ManualResetEvent _stopped = new ManualResetEvent(false);

        public WebSocketListener(IPEndPoint ep, string host, string origin, bool server = true)
        {
            Listener = new TcpListener(ep);

            Host = host;
            Origin = origin;
            Server = server;

            Queue = new BlockingCollection<ITunnel>();

            Utilities.StartThread(AcceptThread);
        }

        public void AcceptThread()
        {
            while (true)
            {
                while (!_stopped.WaitOne(0))
                {
                    try
                    {
                        Queue.Add(new WebSocketTunnel(Listener.AcceptTcpClient(), Host, Origin, Server));
                    }
                    catch (Exception ex)
                    {
                        if (_stopped.WaitOne(0))
                            break;

                        Log.Error(ex);
                    }
                }

                Thread.Sleep(100);
            }
        }

        public ITunnel Accept()
        {
            return Queue.Take();
        }

        public void Start()
        {
            _stopped.Reset();
            Listener.Start();
        }

        public void Stop()
        {
            _stopped.Set();
            Listener.Stop();
        }
    }
}
