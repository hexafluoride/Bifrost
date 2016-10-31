// #define EXTENDED_WEBSOCKET_DEBUG
// uncomment this if you wanna dump websocket frames

// also, too much microoptimization because this is slow for some reason

using NLog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost.WebSockets
{
    public class WebSocketMessage
    {
        public bool Final { get; set; }
        public bool Masked { get; set; }
        public Opcode Opcode { get; set; }

        public byte[] Mask { get; set; }

        public byte[] Payload { get; set; }

        public static Logger Log = LogManager.GetCurrentClassLogger();

        public WebSocketMessage()
        {

        }

        public byte[] Serialize()
        {
            return SerializeInPlace(Final, Masked, Opcode, Payload, Mask);
        }

        public static byte[] SerializeInPlace(bool final, bool masked, Opcode opcode, byte[] payload, byte[] mask)
        {
            byte[] ret = new byte[2 + (payload.Length > 125 ? (payload.Length < ushort.MaxValue ? 2 : 8) : 0) + (masked ? 4 : 0) + payload.Length];

            byte fin_rsv = 0;

            if (final)
                fin_rsv |= 0x80;

            byte first_octet = (byte)(fin_rsv | (byte)opcode);
            byte second_octet = 0;
            byte surrogate_length = 0;

            if (masked)
                second_octet |= 0x80;

            if (payload.Length > 125)
            {
                if (payload.Length < ushort.MaxValue)
                    surrogate_length = 126;
                else
                    surrogate_length = 127;
            }
            else
                surrogate_length = (byte)payload.Length;

            second_octet |= surrogate_length;

            int index = 0;

            ret[0] = first_octet;
            ret[1] = second_octet;

            index += 2;

            if (surrogate_length == 126) // 2^16 > len > 125
            {
                byte[] ext_len = BitConverter.GetBytes((ushort)payload.Length).Reverse().ToArray();
                Array.Copy(ext_len, 0, ret, index, ext_len.Length);
                index += ext_len.Length;
            }
            if (surrogate_length == 127) // 2^64 > len > 2^16
            {
                byte[] ext_len = BitConverter.GetBytes((ulong)payload.Length).Reverse().ToArray();
                Array.Copy(ext_len, 0, ret, index, ext_len.Length);
                index += ext_len.Length;
            }

            if (masked)
            {
                Array.Copy(mask, 0, ret, index, mask.Length);
                index += mask.Length;
            }

            Array.Copy(payload, 0, ret, index, payload.Length);
            index += payload.Length;

            if(masked)
            {
                DecodeMask(ret, mask, index - payload.Length);
            }

            return ret;
        }

        public static RNGCryptoServiceProvider RNG = new RNGCryptoServiceProvider();

        public static WebSocketMessage Create(byte[] payload, Opcode opcode, bool mask = true)
        {
            WebSocketMessage ret = new WebSocketMessage();

            ret.Payload = payload;
            ret.Opcode = opcode;
            ret.Masked = mask;
            ret.Final = true;
            
            if(mask)
            {
                ret.Mask = new byte[4];
                RNG.GetBytes(ret.Mask);
            }

            return ret;
        }

        public static WebSocketMessage FromStream(WebSocketMessage msg, Stream stream)
        {
            byte[] header_proto = stream.ReadShort(2);

            byte fin_rsv = (byte)((header_proto[0] & 0xF0) >> 4);
            byte opcode = (byte)(header_proto[0] & 0x0F);
            bool mask = (header_proto[1] & 0x80) == 0x80;
            ulong length = (ulong)(header_proto[1] & 0x7F);

            msg.Final = (fin_rsv & 0x08) == 0x08;
            msg.Opcode = (Opcode)opcode;
            msg.Masked = mask;

            if (fin_rsv != 0x08)
            {
                Log.Warn("Invalid fin_rsv!");
                Log.Debug("\tfin and rsv: {0}", Convert.ToString(fin_rsv, 2));
                Log.Debug("\topcode: {0}", opcode);
                Log.Debug("\tmask: {0}", mask ? 1 : 0);
                Log.Debug("\tlength: {0}", length);
                return null;
            }

#if EXTENDED_WEBSOCKET_DEBUG
            Log.Info("Incoming packet:");
            Log.Info("\tfin and rsv: {0}", Convert.ToString(fin_rsv, 2));
            Log.Info("\topcode: {0}", opcode);
            Log.Info("\tmask: {0}", mask ? 1 : 0);
            Log.Info("\tlength: {0}", length);*/
#endif

            if (length == 126)
            {
                length = BitConverter.ToUInt16(stream.ReadShort(2, true), 0);
#if EXTENDED_WEBSOCKET_DEBUG
                //Log.Info("Extended packet length(0-2^16): {0}", length);
#endif
            }
            else if (length == 127)
            {
                length = BitConverter.ToUInt64(stream.ReadShort(8, true), 0);
#if EXTENDED_WEBSOCKET_DEBUG
                //Log.Info("Extended packet length(0-2^64): {0}", length);
#endif
            }

            byte[] mask_key = new byte[4];

            if (mask)
            {
                mask_key = stream.ReadShort(4);
#if EXTENDED_WEBSOCKET_DEBUG
                //Log.Info("Mask key is {0}", BitConverter.ToString(mask_key).Replace("-", "").ToLower());
#endif
            }

            msg.Mask = mask_key;

            if (length == 0)
            {
                msg.Payload = new byte[0];
                return msg;
            }

            byte[] buf = stream.ReadSafe((uint)length);

            if (mask)
                buf = DecodeMask(buf, mask_key);

            msg.Payload = buf;

            return msg;
        }

        public static WebSocketMessage FromStream(Stream stream)
        {
            WebSocketMessage ret = new WebSocketMessage();
            return FromStream(ret, stream);
        }

        static byte[] DecodeMask(byte[] data, byte[] mask, int start = 0)
        {
            for (int i = 0; i < data.Length - start; i++)
                data[i + start] ^= mask[i % 4];

            return data;
        }

        public static WebSocketMessage FromRaw(byte[] data)
        {
            MemoryStream ms = new MemoryStream(data);
            return FromStream(ms);
        }
    }

    public enum Opcode
    {
        Continuation = 0x00,
        Text = 0x01,
        Binary = 0x02,
        Close = 0x08,
        Ping = 0x09,
        Pong = 0x0A
    }
}
