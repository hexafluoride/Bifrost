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

namespace Bifrost
{
    public delegate void DataReceived(EncryptedLink link, byte[] data);
    public delegate void LinkClosed(EncryptedLink link);

    /// <summary>
    /// A general purpose encrypted link that both ClientLink and ServerLink inherit from.
    /// For most applications, it's better to use ClientLink/ServerLink unless you have to implement your own handshake logic, which is not recommended.
    /// </summary>
    public class EncryptedLink
    {
        public ITunnel Tunnel { get; set; }
        public EncryptionMode CurrentEncryption = EncryptionMode.None;

        public AsymmetricCipherKeyPair Certificate;
        public RsaKeyParameters CertificateAuthority;
        public byte[] Signature;

        public ECDHBasicAgreement KeyAgreement = new ECDHBasicAgreement();
        public AsymmetricCipherKeyPair ECDHEPair;
        public readonly string HKDFAdditionalInfo =
            "cipher-aes256-gcm\n" +
            "application-bifrost\n" +
            "key-exchange-ecdhe-rsa\n";

        public GcmBlockCipher AES;
        public SHA256CryptoServiceProvider SHA = new SHA256CryptoServiceProvider();
        public HMACSHA256 HMAC = new HMACSHA256();

        public event DataReceived OnDataReceived;
        public event LinkClosed OnLinkClosed;

        public bool BufferedWrite = false;
        public bool Dead = false;

        public TimeSpan MaximumTimeMismatch = new TimeSpan(0, 5, 0);

        public SizeQueue<Message> SendQueue = new SizeQueue<Message>(1500);
            
        public RNGCryptoServiceProvider RNG = new RNGCryptoServiceProvider();

        protected byte[] SecretKey = new byte[32];
        protected byte[] MACKey = new byte[32];

        public KeyParameter AESKey;

        public byte[] SharedSalt;

        private Logger Log = LogManager.GetCurrentClassLogger();

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
            CertificateAuthority = (RsaKeyParameters)RsaHelpers.PemDeserialize(File.ReadAllText(ca_path));
            Log.Trace("Loaded certificate authority from {0}", ca_path);
            Certificate = (AsymmetricCipherKeyPair)RsaHelpers.PemDeserialize(File.ReadAllText(key_path));
            Log.Trace("Loaded certificate from {0}", key_path);

            Signature = File.ReadAllBytes(sign_path);
            Log.Trace("Loaded signature from {0}", sign_path);

            GenerateECDHEKeyPair();
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
            Log.Trace("Loaded certificate authority.");

            Certificate = (AsymmetricCipherKeyPair)RsaHelpers.PemDeserialize(Encoding.UTF8.GetString(Convert.FromBase64String(key)));
            Log.Trace("Loaded certificate.");

            Signature = Convert.FromBase64String(sign);
            Log.Trace("Loaded signature.");

            GenerateECDHEKeyPair();
        }

        /// <summary>
        /// Calculates a MAC and key pair using HKDF with the provided secret.
        /// </summary>
        /// <param name="secret">The secret to derive our MAC and key from.</param>
        /// <returns>512 bits worth of data that can be used to derive a MAC and key from.</returns>
        public byte[] CalculateHKDF(byte[] secret)
        {
            HMACSHA512 hmac = new HMACSHA512();

            hmac.Key = SharedSalt;
            byte[] prk = hmac.ComputeHash(secret);

            hmac.Key = prk;
            byte[] k1 = hmac.ComputeHash(Encoding.UTF8.GetBytes(HKDFAdditionalInfo + "\0"));

            return k1;
        }

        /// <summary>
        /// Generates an ECDHE key pair using the P-521 curve.
        /// </summary>
        public void GenerateECDHEKeyPair()
        {
            X9ECParameters ec_parameters = NistNamedCurves.GetByName("P-521");
            ECDomainParameters ec_specs = new ECDomainParameters(ec_parameters.Curve, ec_parameters.G, ec_parameters.N, ec_parameters.H, ec_parameters.GetSeed());
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(ec_specs, new SecureRandom()));
            Log.Trace("Initialized EC key generator with curve P-521");

            ECDHEPair = generator.GenerateKeyPair();
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
        /// Exports our ECDHE public key to a string.
        /// </summary>
        /// <returns>The serialized public key.</returns>
        public string ExportECDHPublicKey()
        {
            StringWriter sw = new StringWriter();
            PemWriter pem = new PemWriter(sw);

            pem.WriteObject(ECDHEPair.Public);
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

            BufferedWrite = true;
        }

        /// <summary>
        /// A loop that receives and parses link messages.
        /// </summary>
        private void ReceiveLoop()
        {
            MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
            while(true)
            {
                if (Tunnel.Closed)
                {
                    Log.Error("HttpTunnel closed, ending ReceiveLoop");

                    if (OnLinkClosed != null)
                        OnLinkClosed(this);

                    return;
                }

                Message msg = Receive();

                if (msg == null)
                {
                    Log.Trace("Null message, continuing");
                    continue;
                }

                lock (msg)
                {
                    if (msg.Type == MessageType.Data)
                    {
                        Tunnel.DataBytesReceived += msg.Store["data"].Length;
                        
                        if (OnDataReceived != null)
                            OnDataReceived(this, msg.Store["data"]);
                    }
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
            byte[] final_message;

            if (raw_message == null || raw_message.Length == 0)
            {
                Log.Trace("Empty read from HttpTunnel");
                return null;
            }

            switch (CurrentEncryption)
            {
                case EncryptionMode.AES:
                    {
                        try
                        {
                            var aes = new GcmBlockCipher(new AesFastEngine());

                            byte[] iv = new byte[16];
                            byte[] ciphertext = new byte[raw_message.Length - iv.Length];

                            Array.Copy(raw_message, iv, iv.Length);
                            Array.Copy(raw_message, iv.Length, ciphertext, 0, ciphertext.Length);

                            var parameters = new AeadParameters(new KeyParameter(SecretKey), 128, iv);
                            aes.Init(false, parameters);

                            final_message = new byte[aes.GetOutputSize(ciphertext.Length)];
                            int len = aes.ProcessBytes(ciphertext, 0, ciphertext.Length, final_message, 0);
                            aes.DoFinal(final_message, len);
                        }
                        catch (Exception ex)
                        {
                            Log.Warn("Invalid MAC! Ignoring message of length {0}.", raw_message.Length);
                            Log.Error(ex);
                            return null;
                        }
                        break;
                    }
                default:
                    final_message = raw_message;
                    break;
            }

            try
            {
                return Message.Parse(final_message);
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

            while (!Tunnel.Closed)
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
            byte[] final_message;

            switch (CurrentEncryption)
            {
                case EncryptionMode.AES:
                    {
                        var aes = new GcmBlockCipher(new AesFastEngine());

                        MemoryStream ms = new MemoryStream();

                        byte[] iv = new byte[16];
                        RNG.GetBytes(iv);

                        var parameters = new AeadParameters(AESKey, 128, iv);
                        aes.Init(true, parameters);

                        var ciphertext = new byte[aes.GetOutputSize(raw_message.Length)];
                        int len = aes.ProcessBytes(raw_message, 0, raw_message.Length, ciphertext, 0);
                        aes.DoFinal(ciphertext, len);

                        ms.Write(iv, 0, iv.Length);
                        ms.Write(ciphertext, 0, ciphertext.Length);

                        final_message = ms.ToArray();
                        break;
                    }
                default:
                    final_message = raw_message;
                    break;
            }
            
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
    }

    /// <summary>
    /// Describes an EncryptedLink's current encryption mode. Should always be AES while sending data.
    /// </summary>
    public enum EncryptionMode
    {
        None, AES
    }
}

