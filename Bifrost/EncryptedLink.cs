using System;
using System.IO;
using System.Security.Cryptography;
using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.OpenSsl;

using NLog;
using Bifrost.Ciphers;
using System.Threading;
using Bifrost.KeyExchanges;
using Bifrost.MACs;

namespace Bifrost
{
    public delegate void MessageReceived(EncryptedLink link, Message msg);
    public delegate void DataReceived(EncryptedLink link, byte[] data);
    public delegate void LinkClosed(EncryptedLink link);

    /// <summary>
    /// A general purpose encrypted link that both ClientLink and ServerLink inherit from.
    /// For most applications, it's better to use ClientLink/ServerLink unless you have to implement your own handshake logic, which is not recommended.
    /// </summary>
    public class EncryptedLink
    {
        public static List<CipherSuiteIdentifier> AllowedSuites = new List<CipherSuiteIdentifier>();
        public static List<CipherSuiteIdentifier> SaneSuites = new List<CipherSuiteIdentifier>()
        {
            new CipherSuiteIdentifier(AesGcmCipher.Identifier, EcdhKeyExchange.Identifier, IdentityMAC.Identifier),
            new CipherSuiteIdentifier(AesCbcCipher.Identifier, EcdhKeyExchange.Identifier, HMACSHA.Identifier),
            new CipherSuiteIdentifier(ChaChaCipher.Identifier, EcdhKeyExchange.Identifier, HMACSHA.Identifier)
        };

        public ITunnel Tunnel { get; set; }
        public CipherSuite Suite { get; set; }

        public bool Closed { get; set; }

        public AsymmetricCipherKeyPair Certificate;
        public RsaKeyParameters CertificateAuthority;
        public byte[] Signature;
        public byte[] PeerSignature;
        
        public SHA256CryptoServiceProvider SHA = new SHA256CryptoServiceProvider();

        // TODO: Go from "event X OnX" to "event OnX X"
        public event MessageReceived OnMessageReceived;
        public event DataReceived OnDataReceived;
        public event LinkClosed OnLinkClosed;

        public bool BufferedWrite = false;

        public bool HeartbeatCapable = false;

        public TimeSpan MaximumTimeMismatch = new TimeSpan(0, 5, 0);

        public SizeQueue<Message> SendQueue = new SizeQueue<Message>(1500);
            
        public RNGCryptoServiceProvider RNG = new RNGCryptoServiceProvider();

        private DateTime _last_received = DateTime.Now;
        private DateTime _last_sent = DateTime.Now;

        private Logger Log = LogManager.GetCurrentClassLogger();

        private Capability LocalCapabilities = // these are not used yet
            Capability.CapabilityNegotiation |
            Capability.Heartbeat |
            Capability.CipherSelection;

        private Capability RemoteCapabilities;

        public byte[] AttestationToken { get; set; }

        public EncryptedLink()
        {
        }

        public EncryptedLink(ITunnel tunnel)
        {
            Tunnel = tunnel;
        }

        /// <summary>
        /// Loads a keypair and signature from the provided paths.
        /// </summary>
        /// <param name="ca_path">The file that contains the certificate authority public key.</param>
        /// <param name="key_path">The file that contains our public/private keypair.</param>
        /// <param name="sign_path">The file that contains our signature.</param>
        public void LoadCertificatesFromFiles(string ca_path, string key_path, string sign_path)
        {
            if (File.Exists(ca_path))
            {
                CertificateAuthority = (RsaKeyParameters)RsaHelpers.PemDeserialize(File.ReadAllText(ca_path));
                Log.Debug("Loaded certificate authority from {0}", ca_path);
            }

            if (File.Exists(key_path))
            {
                Certificate = (AsymmetricCipherKeyPair)RsaHelpers.PemDeserialize(File.ReadAllText(key_path));
                Log.Debug("Loaded certificate from {0}", key_path);
            }

            if (File.Exists(sign_path))
            {
                Signature = File.ReadAllBytes(sign_path);
                Log.Debug("Loaded signature from {0}", sign_path);
            }
        }        

        /// <summary>
        /// Loads a keypair and signature from the provided strings.
        /// </summary>
        /// <param name="ca">The public key of the certificate authority in text form.</param>
        /// <param name="key">Both our public and private key, concatenated, in text form.</param>
        /// <param name="sign">The signature in Base64.</param>
        public void LoadCertificatesFromText(string ca, string key, string sign)
        {
            CertificateAuthority = (RsaKeyParameters)RsaHelpers.PemDeserialize(Encoding.UTF8.GetString(Convert.FromBase64String(ca)));
            Log.Debug("Loaded certificate authority.");

            Certificate = (AsymmetricCipherKeyPair)RsaHelpers.PemDeserialize(Encoding.UTF8.GetString(Convert.FromBase64String(key)));
            Log.Debug("Loaded certificate.");

            Signature = Convert.FromBase64String(sign);
            Log.Debug("Loaded signature.");
        }

        public void Close()
        {
            // send closing message

            try
            {
                SendMessage(new Message(MessageType.Control, 0xFF));
            }
            catch
            {

            }

            // close underlying tunnel
            Tunnel?.Close();

            // unblock SendLoop
            SendQueue.Enqueue(null);

            Closed = true;
            OnLinkClosed?.Invoke(this);
        }

        /// <summary>
        /// Exports our RSA public key to a string.
        /// </summary>
        /// <returns>The serialized public key.</returns>
        public string ExportRSAPublicKey()
        {
            StringWriter sw = new StringWriter();
            PemWriter pem = new PemWriter(sw);

            pem.WriteObject(Certificate.Public);
            pem.Writer.Flush();

            return sw.ToString();
        }

        /// <summary>
        /// Starts the receive/send thread pair.
        /// </summary>
        public void StartThreads()
        {
            Utilities.StartThread(ReceiveLoop);
            Utilities.StartThread(SendLoop);

            BufferedWrite = false;

            SendMessage(new Message(MessageType.Heartbeat, 0)); // signal heartbeat cap
            Utilities.StartThread(KeepAlive);
            Utilities.StartThread(CheckAlive);
        }

        /// <summary>
        /// A loop that receives and parses link messages.
        /// </summary>
        private void ReceiveLoop()
        {
            MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
            while(!Closed)
            {
                if (Tunnel.Closed)
                {
                    Log.Error("ITunnel closed, ending ReceiveLoop");
                    Close();
                    return;
                }

                Message msg = Receive();

                if (msg == null)
                {
                    Log.Trace("Null message, continuing");
                    continue;
                }

                OnMessageReceived?.Invoke(this, msg);
                
                if (msg.Type == MessageType.Data)
                {
                    Tunnel.DataBytesReceived += msg.Store["data"].Length;
                    OnDataReceived?.Invoke(this, msg.Store["data"]);
                }

                if (msg.Type == MessageType.Heartbeat && !HeartbeatCapable)
                {
                    HeartbeatCapable = true;
                }
            }
        }

        /// <summary>
        /// Receives a single message from the underlying ITunnel.
        /// </summary>
        /// <returns>The message received, or null if we failed to read a message.</returns>
        public Message Receive()
        {
            byte[] raw_message = Tunnel.Receive();

            if (raw_message == null || raw_message.Length == 0)
            {
                Log.Trace("Empty read from ITunnel");
                return null;
            }

            var final_message = Suite.Decrypt(raw_message);

            try
            {
                var ret = Message.Parse(final_message);
                _last_received = DateTime.Now;
                return ret;
            }
            catch
            {
                Log.Warn("Corrupt message data, ignoring");
                return null;
            }
        }

        /// <summary>
        /// A loop that sends dequeues and sends messages from the internal outgoing queue.
        /// </summary>
        private void SendLoop()
        {
            while (Tunnel.Closed)
                ;

            while (!Closed)
            {
                Message msg = SendQueue.Dequeue();
                _SendMessage(msg);
            }

            Log.Error("SendLoop exited.");
        }

        /// <summary>
        /// Dynamically sends a message based on the current BufferedWrite value.
        /// </summary>
        /// <param name="msg">The message to send.</param>
        public void SendMessage(Message msg)
        {
            if (!BufferedWrite)
                _SendMessage(msg);
            else
            {
                SendQueue.Enqueue(msg);
            }
        }

        /// <summary>
        /// Directly writes a message into the underlying ITunnel.
        /// </summary>
        /// <param name="msg">The message to send.</param>
        private void _SendMessage(Message msg)
        {
            if (msg == null)
                return;

            if(msg.Type == MessageType.Data)
            {
                Tunnel.DataBytesSent += msg.Store["data"].Length;
            }

            byte[] raw_message = msg.Serialize();
            byte[] final_message = Suite.Encrypt(raw_message);

            _last_sent = DateTime.Now;
            Tunnel.Send(final_message);
        }

        /// <summary>
        /// Helper method for sending raw data using messages.
        /// </summary>
        /// <param name="data">The data to send.</param>
        public void SendData(byte[] data)
        {
            SendMessage(MessageHelpers.CreateDataMessage(data));
        }

        public void CheckAlive()
        {
            Log.Info("Heartbeat capable peer.");

            while ((DateTime.Now - _last_received).TotalSeconds < 10)
                Thread.Sleep(500);

            if(!Closed)
            {
                Close();
            }
        }

        public void KeepAlive()
        {
            while (!Closed)
            {
                SendMessage(new Message(MessageType.Heartbeat, 0));

                while ((DateTime.Now - _last_sent).TotalSeconds < 3)
                    Thread.Sleep(500);
            }
        }
    }
}

