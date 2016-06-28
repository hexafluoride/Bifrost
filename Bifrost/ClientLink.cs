using System;
using System.Text;
using System.IO;
using System.Linq;

using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

using NLog;

namespace Bifrost
{
    public class ClientLink : EncryptedLink
    {
        private Logger Log = LogManager.GetCurrentClassLogger();
        public bool AuthenticateSelf { get; set; }

        /// <summary>
        /// Creates a new EncryptedLink object from the perspective of a server.
        /// </summary>
        /// <param name="tunnel">The ITunnel to use.</param>
        /// <param name="auth_self">If auth_self is set to true, the loaded RSA keys are used to authenticate ourselves to the server. 
        /// If auth_client is set to true on the server, auth_self must also be true, otherwise the handshake will fail.</param>
        public ClientLink(ITunnel tunnel, bool auth_self = true)
        {
            Tunnel = tunnel;
            AuthenticateSelf = auth_self;
        }

        /// <summary>
        /// Perform a client-side handshake.
        /// </summary>
        /// <returns>true if the handshake was successful, false otherwise.</returns>
        public bool PerformHandshake()
        {
            SendMessage(MessageHelpers.CreateECDHERequest(this));

            Message msg = Receive();

            if (msg == null)
            {
                Log.Error("Connection closed?");
                Tunnel.Close();
                return false;
            }

            if (!msg.CheckType(MessageType.AuthResponse, 0x00))
            {
                Log.Error("Received message of type {0}/0x{1:X} while expecting AuthResponse/0x00. Terminating handshake.", msg.Type, msg.Subtype);
                Tunnel.Close();
                return false;
            }

            byte[] rsa_public_key = msg.Store["rsa_public_key"];
            byte[] rsa_signature = msg.Store["rsa_signature"];
            byte[] ecdh_public_key = msg.Store["ecdh_public_key"];
            byte[] ecdh_signature = msg.Store["ecdh_signature"];

            byte[] shared_salt = msg.Store["shared_salt"];
            byte[] salt_signature = msg.Store["shared_salt_signature"];

            if (!RsaHelpers.VerifyData(rsa_public_key, rsa_signature, CertificateAuthority))
            {
                Log.Error("Failed to verify RSA public key against certificate authority. Terminating handshake.", msg.Type, msg.Subtype);
                Tunnel.Close();
                return false;
            }

            var parameters = (RsaKeyParameters)RsaHelpers.PemDeserialize(Encoding.UTF8.GetString(rsa_public_key));

            if (!RsaHelpers.VerifyData(ecdh_public_key, ecdh_signature, parameters))
            {
                Log.Error("Failed to verify ECDH public key authenticity. Terminating handshake.", msg.Type, msg.Subtype);
                Tunnel.Close();
                return false;
            }

            if (!RsaHelpers.VerifyData(shared_salt, salt_signature, parameters))
            {
                Log.Error("Failed to verify shared salt authenticity. Terminating handshake.", msg.Type, msg.Subtype);
                Tunnel.Close();
                return false;
            }

            SharedSalt = shared_salt;

            PemReader pem = new PemReader(new StringReader(Encoding.UTF8.GetString(ecdh_public_key)));

            ECPublicKeyParameters peer_ecdh_pk = (ECPublicKeyParameters)pem.ReadObject();
            ECPrivateKeyParameters self_priv = ECDHEPair.Private as ECPrivateKeyParameters;

            IBasicAgreement agreement = AgreementUtilities.GetBasicAgreement("ECDH");
            agreement.Init(self_priv);

            var shared_secret = agreement.CalculateAgreement(peer_ecdh_pk).ToByteArray();

            byte[] prekey = CalculateHKDF(shared_secret);
            Array.Copy(prekey, 0, SecretKey, 0, 32);
            Array.Copy(prekey, 32, MACKey, 0, 32);

            AES = new GcmBlockCipher(new AesFastEngine());
            AESKey = new KeyParameter(SecretKey);
            HMAC.Key = MACKey;

            CurrentEncryption = EncryptionMode.AES;

            Log.Info("Handshake successful.");

            return true;
        }
    }
}

