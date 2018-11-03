using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using NLog;
using System.IO;
using System.Runtime.CompilerServices;

namespace Bifrost.Udp
{
    internal class UdpSession
    {
        public UdpClient Socket { get; set; }
        public UdpListener Listener { get; set; }
        public IPEndPoint EndPoint { get; set; }

        public int ForceMTU = 0;
        public ulong DroppedFragments = 0;
        public ulong ReceivedFragments = 0;

        internal BlockingCollection<byte[]> ReceiveQueue = new BlockingCollection<byte[]>();
        internal bool L7FragmentationCapable = false;

        internal List<int> GoodMTUs = new List<int>();
        internal DateTime LastMTUProbe = DateTime.Now;

        internal int PeerMTU = 0;
        internal bool NegotiatingMTU = false;

        internal ulong[] FragmentIDs = new ulong[FRAGMENT_SLOT_COUNT];
        internal byte[][] FragmentSlots = new byte[FRAGMENT_SLOT_COUNT][];
        internal ushort[] FragmentFill = new ushort[FRAGMENT_SLOT_COUNT];

        internal const int MAX_FRAGMENT_LEN = 4096;
        internal const int FRAGMENT_SLOT_COUNT = 256;

        Logger Log = LogManager.GetCurrentClassLogger();
        
        public UdpSession(UdpClient socket, UdpListener listener, IPEndPoint endpoint)
        {
            Socket = socket;
            Listener = listener;
            EndPoint = endpoint;
        }

        public const int SYN = 0x01;
        public const int SYN_ACK = 0x02;
        public const int ACK = 0x04;

        public static int HANDSHAKE_TIMEOUT = 5000;

        public void Connect()
        {
            Message syn_msg = new Message(MessageType.Control, SYN);
            Send(syn_msg.Serialize());

            var resp = ReceiveMessage(HANDSHAKE_TIMEOUT);

            if (resp == null || resp.Type != MessageType.Control || resp.Subtype != SYN_ACK)
                throw new Exception("Failed to connect");

            if (resp.Store.ContainsKey("capabilities"))
            {
                L7FragmentationCapable = resp.Store["capabilities"].Contains((byte)UdpCapabilities.L7Fragmentation);
            }

            Message ack_msg = new Message(MessageType.Control, ACK);
            ack_msg.Store["capabilities"] = new byte[] { (byte)UdpCapabilities.L7Fragmentation };

            Send(ack_msg.Serialize());

            if (L7FragmentationCapable)
                NegotiateMTU();
        }

        internal void NegotiateMTU()
        {
            NegotiatingMTU = true; // this is so Send() doesn't get confused
            Socket.DontFragment = true;
            Thread.Sleep(100); 
            int start_mtu = 576;
            int end_mtu = 1600;
            int interval = 16;

            int packet_count = 5;

            if (ForceMTU != 0)
            {
                Log.Warn("Forcing MTU to {0}, this might have unexpected effects.", ForceMTU);
                start_mtu = ForceMTU;
                end_mtu = start_mtu + interval;
            }

            var mtu_special = Encoding.ASCII.GetBytes("MTU ");

            for(int mtu = start_mtu; mtu < end_mtu; mtu += interval)
            {
                Log.Trace("  probing MTU {0}...", mtu);

                MemoryStream ms = new MemoryStream();
                BinaryWriter bw = new BinaryWriter(ms);

                bw.Write(mtu_special);
                bw.Write(mtu);
                bw.Write(new byte[mtu - ms.Position]);

                var packet = ms.ToArray();

                for(int i = 0; i < packet_count; i++)
                {
                    try
                    {
                        Socket.Send(packet, packet.Length, EndPoint);
                    }
                    catch
                    {

                    }
                }
            }

            LastMTUProbe = DateTime.Now;
            while ((DateTime.Now - LastMTUProbe).TotalMilliseconds < 500 && GoodMTUs.Count < 1000) // prevent attack
                Thread.Sleep(100);

            var good_mtu = 0;

            if (ForceMTU != 0)
                good_mtu = ForceMTU;
            else
                good_mtu = GoodMTUs.Max();

            Log.Info("Detected downlink MTU: {0}", good_mtu);

            Message message = new Message(MessageType.Control, 0x53);
            message.Store["mtu"] = BitConverter.GetBytes(good_mtu);

            Send(message.Serialize());

            var peer_mtu_msg = ReceiveMessage(5000);
            
            if(!peer_mtu_msg.CheckType(MessageType.Control, 0x53))
            {
                Log.Warn("Received message of type {0}/0x{1:X} while expecting MTU notification. pMTUd has failed.", peer_mtu_msg.Type, peer_mtu_msg.Subtype);
                return;
            }

            PeerMTU = BitConverter.ToInt32(peer_mtu_msg.Store["mtu"], 0);

            if (ForceMTU != 0)
                PeerMTU = ForceMTU;

            Log.Info("Detected uplink MTU: {0}", PeerMTU);

            Socket.DontFragment = false;
            NegotiatingMTU = false;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal void HandleFragment(byte[] fragment)
        {
            if (fragment[0] != 'f')
            {
                var _tmp = new byte[fragment.Length - 1];
                Array.Copy(fragment, 1, _tmp, 0, _tmp.Length);
                Push(_tmp);
                return;
            }

            var slot_id = BitConverter.ToUInt64(fragment, 1);
            var slot_id_small = (byte)(slot_id % 256);
            var total_length = BitConverter.ToUInt16(fragment, 9);
            var index = BitConverter.ToUInt16(fragment, 11);

            var fragment_length = fragment.Length - 13;

            if (total_length >= MAX_FRAGMENT_LEN || index + fragment_length > total_length || slot_id_small > FRAGMENT_SLOT_COUNT)
                throw new Exception("Invalid fragment");

            // packet loss reporting

            if(slot_id_small == 0) // check whenever the "small" fragment slot identifier wraps around
            {
                ulong max_fragment_id = 0;
                ulong min_fragment_id = ulong.MaxValue;

                for(int i = 0; i < FragmentIDs.Length; i++)
                {
                    var fragment_id = FragmentIDs[i];

                    if (fragment_id > max_fragment_id)
                        max_fragment_id = fragment_id;

                    if (fragment_id < min_fragment_id)
                        min_fragment_id = fragment_id;
                }

                var expected_fragments = max_fragment_id - min_fragment_id;
                var received_fragments = (ulong)FragmentIDs.Length;

                DroppedFragments += expected_fragments - received_fragments;
            }

            var slot = FragmentSlots[slot_id_small];

            if(FragmentSlots[slot_id_small] == null || FragmentIDs[slot_id_small] != slot_id || FragmentSlots[slot_id_small].Length != total_length)
            {
                slot = FragmentSlots[slot_id_small] = new byte[total_length];
                FragmentFill[slot_id_small] = 0;
                FragmentIDs[slot_id_small] = slot_id;
            }

            Array.Copy(fragment, 13, FragmentSlots[slot_id_small], index, fragment_length);
            FragmentFill[slot_id_small] += (ushort)fragment_length;

            if(FragmentFill[slot_id_small] == total_length)
            {
                Push(FragmentSlots[slot_id_small]);
                FragmentSlots[slot_id_small] = null;
            }

            ReceivedFragments++;
        }

        private ulong _fragment_index = 0;

        internal void SendFragmented(byte[] data)
        {
            if (data.Length > MAX_FRAGMENT_LEN)
                throw new Exception("Datagram bigger than MAX_FRAGMENT_LEN");

            int fragment_count = (int)Math.Ceiling((float)data.Length / (float)PeerMTU);

            byte[][] fragments = new byte[fragment_count][];

            for(int i = 0, index = 0; i < fragment_count; i++)
            {
                int left = data.Length - index;

                var fragment = new byte[Math.Min(PeerMTU, left + 13)];
                fragment[0] = (byte)'f';
                //fragment[1] = _fragment_index;

                Array.Copy(BitConverter.GetBytes(_fragment_index), 0, fragment, 1, 8);

                Array.Copy(BitConverter.GetBytes((ushort)data.Length), 0, fragment, 9, 2);
                Array.Copy(BitConverter.GetBytes((ushort)index), 0, fragment, 11, 2);

                Array.Copy(data, index, fragment, 13, fragment.Length - 13);
                index += fragment.Length - 13;

                fragments[i] = fragment;
            }

            for(int i = 0; i < fragment_count; i++)
            {
                _Send(fragments[i]);
            }

            _fragment_index++;
        }

        internal Message ReceiveMessage(int timeout)
        {
            Message response = null;

            for (int i = 0; i < 3; i++)
            {
                var data = Receive(timeout);

                if (data == null || data.Length == 0)
                    continue;

                try
                {
                    response = Message.Parse(data);

                    if (response == null)
                        continue;

                    break;
                }
                catch
                {
                    continue;
                }
            }

            return response;
        }

        internal void Push(byte[] data)
        {
            if (data.Length == 0)
                return;

            ReceiveQueue.Add(data);
        }

        public byte[] Receive()
        {
            var ret = ReceiveQueue.Take();
            return ret;
        }

        public byte[] Receive(CancellationToken token)
        {
            var ret = ReceiveQueue.Take(token);
            return ret;
        }

        public byte[] Receive(int timeout)
        {
            var token = new CancellationTokenSource(timeout);
            return Receive(token.Token);
        }

        private void _Send(byte[] data)
        {
            Socket.Send(data, data.Length, EndPoint);
        }

        public void Send(byte[] data)
        {
            if (L7FragmentationCapable && !NegotiatingMTU && PeerMTU > 0)
            {
                if (data.Length > PeerMTU)
                {
                    SendFragmented(data);
                }
                else
                {
                    var _tmp_buf = new byte[data.Length + 1];
                    Array.Copy(data, 0, _tmp_buf, 1, data.Length);
                    _Send(_tmp_buf);
                }
            }
            else
                _Send(data);
        }
    }
}
