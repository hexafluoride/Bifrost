using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using NLog;
using System.Net.Sockets;

namespace Bifrost
{
    public static class Extensions
    {
        static Logger Log = LogManager.GetCurrentClassLogger();

        public static uint ReadUInt(this Stream stream)
        {
            byte[] buf = stream.ReadSafe(4);

            return BitConverter.ToUInt32(buf, 0);
        }

        public static int ReadInt(this Stream stream)
        {
            byte[] buf = stream.ReadSafe(4);

            return BitConverter.ToInt32(buf, 0);
        }

        public static byte[] ReadSafe(this Stream stream, uint len)
        {
            byte[] buf = new byte[len];
            int index = 0;

            while(true)
            {
                int read = stream.Read(buf, index, buf.Length - index);
                index += read;

                if (index >= (len - 1))
                    break;

                if (read == -1)
                    break;
            }

            return buf;
        }

        public static void WriteUInt(this Stream stream, uint val)
        {
            stream.Write(BitConverter.GetBytes(val), 0, 4);
        }

        public static void WriteInt(this Stream stream, int val)
        {
            stream.Write(BitConverter.GetBytes(val), 0, 4);
        }

        public static string ReadLine(this Stream stream)
        {
            StringBuilder sb = new StringBuilder();

            int b = stream.ReadByte();

            while (b > 0 && b != (byte)'\n')
            {
                sb.Append((char)b);
                b = stream.ReadByte();
            }

            if (b < 0)
            {
                Log.Trace("b is less than 0: {0}", b);
                throw new Exception("Connection closed");
            }

            return sb.ToString();
        }

        public static byte[] ReadToEnd(this Stream stream)
        {
            MemoryStream ms = new MemoryStream();

            stream.CopyTo(ms);

            var ret = ms.ToArray();
            ms.Close();
            return ret;
        }
    }
}

