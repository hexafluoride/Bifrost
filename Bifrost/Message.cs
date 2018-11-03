using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

using NLog;

namespace Bifrost
{
    /// <summary>
    /// A message class used for all communications. Implements a data store with keys for better futureproofing.
    /// </summary>
    public class Message
    {
        public MessageType Type = MessageType.Reserved;
        public byte Subtype = 0x00;
        public Dictionary<string, byte[]> Store;

        public static readonly uint MAGIC = 5;

        private Logger Log = LogManager.GetCurrentClassLogger();

        private Message()
        {

        }

        public Message(MessageType type, byte subtype)
        {
            Type = type;
            Subtype = subtype;
            Store = new Dictionary<string, byte[]>();
        }

        /// <summary>
        /// Parses the provided data and returns a <c>Message</c>.
        /// </summary>
        /// <param name="raw">The data to be parsed.</param>
        public static Message Parse(byte[] raw)
        {
            uint read_magic = BitConverter.ToUInt32(raw, 0);

            if (read_magic != MAGIC)
            {
                throw new Exception("Invalid magic number!");
            }

            Message msg = new Message();

            msg.Type = (MessageType)raw[4];
            msg.Subtype = raw[5];
            msg.Store = GetByteStore(raw, 6);

            return msg;
        }

        /// <summary>
        /// Syntactic sugar for checking if message is of desired type.
        /// </summary>
        /// <returns><c>true</c>, if the provided parameters match this message's type, <c>false</c> otherwise.</returns>
        public bool CheckType(MessageType type, byte subtype)
        {
            return Type == type && Subtype == subtype;
        }

        /// <summary>
        /// Serialize this instance.
        /// </summary>
        public byte[] Serialize()
        {
            MemoryStream ms = new MemoryStream();

            Serialize(ms);

            return ms.ToArray();
        }

        /// <summary>
        /// Serialize this instance to the specified stream.
        /// </summary>
        /// <param name="stream">The output stream.</param>
        public void Serialize(Stream stream)
        {
            stream.WriteUInt(MAGIC);
            stream.WriteByte((byte)Type);
            stream.WriteByte(Subtype);

            SerializeStore(stream);
        }

        /// <summary>
        /// Serializes the data store.
        /// </summary>
        /// <param name="stream">The stream to write the serialized data to.</param>
        private void SerializeStore(Stream stream)
        {
            stream.WriteInt(Store.Count);

            foreach(var pair in Store)
            {
                byte[] str_raw = Encoding.UTF8.GetBytes(pair.Key);

                stream.WriteInt(str_raw.Length);
                stream.Write(str_raw, 0, str_raw.Length);

                stream.WriteInt(pair.Value.Length);
                stream.Write(pair.Value, 0, pair.Value.Length);
            }
        }

        /// <summary>
        /// Serializes the data store.
        /// </summary>
        /// <returns>The data store in serialized form.</returns>
        private byte[] SerializeStore()
        {
            MemoryStream ms = new MemoryStream();
            SerializeStore(ms);

            byte[] ret = ms.ToArray();
            ms.Close();

            return ret;
        }

        /// <summary>
        /// Deserializes a data store from a given byte array and index.
        /// </summary>
        /// <returns>The deserialized byte store.</returns>
        /// <param name="raw">Raw data.</param>
        /// <param name="index">The index of the serialized data.</param>
        private static Dictionary<string, byte[]> GetByteStore(byte[] raw, int index)
        {
            MemoryStream ms = new MemoryStream(raw);
            ms.Seek(index, SeekOrigin.Begin);

            Dictionary<string, byte[]> ret = new Dictionary<string, byte[]>();

            int count = ms.ReadInt();

            while(count-- > 0 && ms.Length != ms.Position + 1)
            {
                int str_len = ms.ReadInt();
                byte[] str_raw = new byte[str_len];
                ms.Read(str_raw, 0, str_len);
                string str = Encoding.UTF8.GetString(str_raw);

                int data_len = ms.ReadInt();
                byte[] data = new byte[data_len];
                ms.Read(data, 0, data_len);

                ret.Add(str, data);
            }

            return ret;
        }
    }

    public enum MessageType
    {
        Reserved = 0x00,
        Control = 0x01,
        Data = 0x02,
        Heartbeat = 0x03,
        ClientHello = 0xFB,
        ServerHello = 0xFC,
        AuthRequest = 0xFD,
        AuthResponse = 0xFE,
        AuthFinalize = 0xFF
    }
}

