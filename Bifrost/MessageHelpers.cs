using System;
using System.Text;
using System.Linq;

using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;

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
            //lock (MD5)
            //{
            //    msg.Store["checksum"] = MD5.ComputeHash(data);
            //}

            return msg;
        }

        /// <summary>
        /// Creates a new handshake request(client-side) and returns it.
        /// </summary>
        /// <param name="link">The ClientLink to create the request packet for.</param>
        /// <returns>The created message.</returns>
        public static Message CreateAuthRequest(ClientLink link)
        {
            Message msg = new Message(MessageType.AuthRequest, 0x00);

            byte[] timestamp = GetTimestamp();

            msg.Store["ecdh_public_key"] = link.Suite.GetKeyExchangeData().Concat(timestamp).ToArray();
            msg.Store["timestamp"] = timestamp;

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

            if (link.AttestationToken != null)
                msg.Store["attestation_token"] = link.AttestationToken;

            return msg;
        }

        public static Message CreateClientHello(ClientLink link, List<CipherSuiteIdentifier> allowed_suites)
        {
            Message msg = new Message(MessageType.ClientHello, 0x00);

            MemoryStream ms = new MemoryStream();
            
            for(int i = 0; i < allowed_suites.Count; i++)
            {
                byte[] serialized = allowed_suites[i].Serialize();

                ms.Write(serialized, 0, serialized.Length);
            }

            msg.Store["allowed_suites"] = ms.ToArray();

            ms.Close();

            return msg;
        }

        public static Message CreateServerHello(ServerLink link, CipherSuiteIdentifier chosen_suite)
        {
            Message msg = new Message(MessageType.ServerHello, 0x00);

            msg.Store["chosen_suite"] = chosen_suite == null ? new byte[0] : chosen_suite.Serialize();

            return msg;
        }

        /// <summary>
        /// Creates a new handshake response(server-side) and returns it.
        /// </summary>
        /// <param name="link">The ServerLink to create the resposne packet for.</param>
        /// <returns>The created message.</returns>
        public static Message CreateAuthResponse(EncryptedLink link)
        { 
            Message msg = new Message(MessageType.AuthResponse, 0x00);

            byte[] timestamp = GetTimestamp();

            msg.Store["rsa_public_key"] = Encoding.UTF8.GetBytes(RsaHelpers.PemSerialize(link.Certificate.Public));
            msg.Store["rsa_signature"] = link.Signature;
            msg.Store["ecdh_public_key"] = link.Suite.GetKeyExchangeData().Concat(timestamp).ToArray();
            msg.Store["ecdh_signature"] = RsaHelpers.SignData(msg.Store["ecdh_public_key"], link.Certificate);

            msg.Store["shared_salt"] = link.Suite.SharedSalt;
            msg.Store["shared_salt_signature"] = RsaHelpers.SignData(link.Suite.SharedSalt, link.Certificate);

            msg.Store["timestamp"] = timestamp;

            return msg;
        }

        static DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static byte[] GetTimestamp()
        {
            return BitConverter.GetBytes((long)(DateTime.UtcNow - Epoch).TotalMilliseconds);
        }
        public static DateTime GetDateTime(long timestamp)
        {
            return Epoch.AddMilliseconds(timestamp);
        }
    }
}

