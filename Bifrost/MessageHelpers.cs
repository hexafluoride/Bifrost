using System;
using System.Text;

using System.Security.Cryptography;

namespace Bifrost
{
    public static class MessageHelpers
    {
        public static MD5CryptoServiceProvider MD5 = new MD5CryptoServiceProvider();

        /// <summary>
        /// Creates and returns a new message of type MessageType.Data with the provided data.
        /// </summary>
        /// <param name="data">The data to include in the message.</param>
        /// <returns>The created message.</returns>
        public static Message CreateDataMessage(byte[] data)
        {
            Message msg = new Message(MessageType.Data, 0x00);

            msg.Store["data"] = data;
            lock (MD5)
            {
                msg.Store["checksum"] = MD5.ComputeHash(data);
            }

            return msg;
        }

        /// <summary>
        /// Creates a new handshake request(client-side) and returns it.
        /// </summary>
        /// <param name="link">The ClientLink to create the request packet for.</param>
        /// <returns>The created message.</returns>
        public static Message CreateECDHERequest(ClientLink link)
        {
            Message msg = new Message(MessageType.AuthRequest, 0x00);

            msg.Store["ecdh_public_key"] = Encoding.UTF8.GetBytes(link.ExportECDHPublicKey());

            if (link.AuthenticateSelf)
            {
                msg.Store["rsa_public_key"] = Encoding.UTF8.GetBytes(RsaHelpers.PemSerialize(link.Certificate.Public));
                msg.Store["rsa_signature"] = link.Signature;
                msg.Store["ecdh_signature"] = RsaHelpers.SignData(msg.Store["ecdh_public_key"], link.Certificate);
            }
            else
            {
                msg.Store["rsa_public_key"] = new byte[0];
                msg.Store["rsa_signature"] = new byte[0];
                msg.Store["ecdh_signature"] = new byte[0];
            }

            return msg;
        }

        /// <summary>
        /// Creates a new handshake response(server-side) and returns it.
        /// </summary>
        /// <param name="link">The ServerLink to create the resposne packet for.</param>
        /// <returns>The created message.</returns>
        public static Message CreateECDHEResponse(EncryptedLink link)
        { 
            Message msg = new Message(MessageType.AuthResponse, 0x00);

            msg.Store["rsa_public_key"] = Encoding.UTF8.GetBytes(RsaHelpers.PemSerialize(link.Certificate.Public));
            msg.Store["rsa_signature"] = link.Signature;
            msg.Store["ecdh_public_key"] = Encoding.UTF8.GetBytes(link.ExportECDHPublicKey());
            msg.Store["ecdh_signature"] = RsaHelpers.SignData(msg.Store["ecdh_public_key"], link.Certificate);

            msg.Store["shared_salt"] = link.SharedSalt;
            msg.Store["shared_salt_signature"] = RsaHelpers.SignData(link.SharedSalt, link.Certificate);

            return msg;
        }
    }
}

