using Bifrost.Ciphers;
using Bifrost.KeyExchanges;
using Bifrost.MACs;
using NLog;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Bifrost
{
    public class CipherSuiteIdentifier
    {
        public const int IdentifierLength = 6;

        public ushort Cipher { get; set; }
        public ushort KeyExchange { get; set; }
        public ushort MAC { get; set; }

        public CipherSuiteIdentifier(byte[] id)
            : this(id, 0)
        {
        }

        public CipherSuiteIdentifier(byte[] id, int start)
        {
            Cipher = BitConverter.ToUInt16(id, start);
            KeyExchange = BitConverter.ToUInt16(id, start + 2);
            MAC = BitConverter.ToUInt16(id, start + 4);
        }

        public CipherSuiteIdentifier(ushort cipher, ushort kex, ushort mac)
        {
            Cipher = cipher;
            KeyExchange = kex;
            MAC = mac;
        }

        public CipherSuite CreateSuite()
        {
            return new CipherSuite()
            {
                Cipher = SuiteRegistry.CreateCipher(Cipher),
                KeyExchange = SuiteRegistry.CreateKeyExchange(KeyExchange),
                MAC = SuiteRegistry.CreateMAC(MAC)
            };
        }

        public byte[] Serialize()
        {
            byte[] ret = new byte[IdentifierLength];
            Array.Copy(BitConverter.GetBytes(Cipher), 0, ret, 0, 2);
            Array.Copy(BitConverter.GetBytes(KeyExchange), 0, ret, 2, 2);
            Array.Copy(BitConverter.GetBytes(MAC), 0, ret, 4, 2);

            return ret;
        }

        public override bool Equals(object obj)
        {
            if (obj == null || GetType() != obj.GetType())
                return false;

            var suite = (CipherSuiteIdentifier)obj;

            return Cipher == suite.Cipher && KeyExchange == suite.KeyExchange && MAC == suite.MAC;
        }

        public override int GetHashCode()
        {
            var arr = Serialize();

            if (arr == null || arr.Length == 0)
                return 0;

            var hash = 0;
            for (var i = 0; i < arr.Length; i++)
                hash = (hash << 3) | (hash >> (29)) ^ arr[i];

            return hash;
        }

        public static bool operator ==(CipherSuiteIdentifier a, CipherSuiteIdentifier b)
        {
            return a.Equals(b);
        }

        public static bool operator !=(CipherSuiteIdentifier a, CipherSuiteIdentifier b)
        {
            return !a.Equals(b);
        }
    }

    public class CipherSuite
    {
        public Logger Log = LogManager.GetCurrentClassLogger();

        public ICipher Cipher { get; set; }
        public IKeyExchange KeyExchange { get; set; }
        public IMAC MAC { get; set; }

        public byte[] SharedSalt { get; set; }

        public string HKDFAdditionalInfo =
            "cipher-{0}\n" +
            "application-bifrost\n" +
            "key-exchange-{1}\n";

        internal CipherSuite()
        {

        }

        public byte[] Encrypt(byte[] data)
        {
            // encrypt-then-MAC to protect against oracle attacks

            var ciphertext = Cipher.Encrypt(data);
            var mac = MAC.Calculate(ciphertext);

            var full_text = new byte[ciphertext.Length + mac.Length];

            Array.Copy(ciphertext, 0, full_text, 0, ciphertext.Length);
            Array.Copy(mac, 0, full_text, ciphertext.Length, mac.Length);

            return full_text;
        }

        public byte[] Decrypt(byte[] data)
        {
            var ciphertext = new byte[data.Length - MAC.OutputLength];
            var mac = new byte[MAC.OutputLength];

            Array.Copy(data, 0, ciphertext, 0, ciphertext.Length);
            Array.Copy(data, ciphertext.Length, mac, 0, mac.Length);

            var calculated_mac = MAC.Calculate(ciphertext);

            if (!calculated_mac.SequenceEqual(mac))
            {
                Log.Warn("Invalid MAC: Expected {0}, got {1} (len={2})", calculated_mac.ToUsefulString(), mac.ToUsefulString(), data.Length);
                return new byte[0]; // corrupt MAC
            }

            return Cipher.Decrypt(data);
        }

        public byte[] GetKeyExchangeData()
        {
            return KeyExchange.GetPublicKey();
        }

        /// <summary>
        /// Finalize the key exchange, preparing the CipherSuite for actual use.
        /// </summary>
        /// <param name="peer_pk">Our peer's private key/key exchange information.</param>
        /// <returns>The raw shared secret.</returns>
        public byte[] FinalizeKeyExchange(byte[] peer_pk)
        {
            var shared = KeyExchange.FinalizeKeyExchange(peer_pk);

            HKDFAdditionalInfo = string.Format(HKDFAdditionalInfo, Cipher.HumanName, KeyExchange.HumanName);

            Cipher.Initialize(CalculateHKDF(shared, Cipher.SecretBytes));
            MAC.Initialize(CalculateHKDF(shared, MAC.SecretBytes));

            return shared;
        }

        public void Initialize()
        {
            KeyExchange.Initialize();
        }

        /// <summary>
        /// Calculates a MAC and key pair using HKDF with the provided secret.
        /// </summary>
        /// <param name="secret">The secret to derive our MAC and key from.</param>
        /// <param name="length">The length of cryptographically secure random sequence to generate, in bytes.</param>
        /// <returns><paramref name="length"/> bytes worth of data that can be used to derive a MAC and key from.</returns>
        public byte[] CalculateHKDF(byte[] secret, int length)
        {
            if (length == 0)
                return new byte[0];

            HMACSHA512 hmac = new HMACSHA512()
            {
                Key = SharedSalt
            };

            int hmac_length = hmac.HashSize / 8;

            byte[] prk = hmac.ComputeHash(secret);
            hmac.Key = prk;

            uint blocks = (uint)Math.Ceiling((double)length / (double)hmac_length) - 1;
            using (MemoryStream ms = new MemoryStream())
            {
                byte[] ctx = Encoding.UTF8.GetBytes(HKDFAdditionalInfo);
                byte[] last_k = hmac.ComputeHash(ctx.Concat(BitConverter.GetBytes((uint)0)).ToArray());

                ms.Write(last_k, 0, last_k.Length);

                for (uint i = 1; i < blocks; i++)
                {
                    byte[] k_n = hmac.ComputeHash(last_k.Concat(ctx).Concat(BitConverter.GetBytes(i)).ToArray());
                    last_k = k_n;

                    ms.Write(k_n, 0, k_n.Length);
                }

                var output = ms.ToArray();
                byte[] ret = new byte[length];

                Array.Copy(output, ret, length);
                return ret;
            }
        }
    }

    public static class SuiteRegistry
    {
        public static Logger Log = LogManager.GetCurrentClassLogger();
        public static Dictionary<ushort, Type> CipherTypes = new Dictionary<ushort, Type>();
        public static Dictionary<ushort, Type> KeyExchangeTypes = new Dictionary<ushort, Type>();
        public static Dictionary<ushort, Type> MACTypes = new Dictionary<ushort, Type>();

        public static bool Initialized = false;

        public static void RegisterCipher(ushort id, Type type)
        {
            if (CipherTypes.ContainsKey(id))
                Log.Warn("Entry {0}/0x{0:X2} being overridden in RegisterCipher!", id);

            CipherTypes[id] = type;
        }

        public static void RegisterKeyExchange(ushort id, Type type)
        {
            if (KeyExchangeTypes.ContainsKey(id))
                Log.Warn("Entry {0}/0x{0:X2} being overridden in RegisterKeyExchange!", id);

            KeyExchangeTypes[id] = type;
        }

        public static void RegisterMAC(ushort id, Type type)
        {
            if (MACTypes.ContainsKey(id))
                Log.Warn("Entry {0}/0x{0:X2} being overridden in RegisterMAC!", id);

            MACTypes[id] = type;
        }

        public static ICipher CreateCipher(ushort id)
        {
            if (!CipherTypes.ContainsKey(id))
                throw new Exception(string.Format("Unknown cipher id {0}/0x{0:X2}", id));

            return (ICipher)Activator.CreateInstance(CipherTypes[id]);
        }

        public static IKeyExchange CreateKeyExchange(ushort id)
        {
            if (!KeyExchangeTypes.ContainsKey(id))
                throw new Exception(string.Format("Unknown key exchange id {0}/0x{0:X2}", id));

            return (IKeyExchange)Activator.CreateInstance(KeyExchangeTypes[id]);
        }

        public static IMAC CreateMAC(ushort id)
        {
            if (!MACTypes.ContainsKey(id))
                throw new Exception(string.Format("Unknown MAC id {0}/0x{0:X2}", id));

            return (IMAC)Activator.CreateInstance(MACTypes[id]);
        }

        public static void Initialize()
        {
            RegisterCipher(AesCbcCipher.Identifier, typeof(AesCbcCipher));
            RegisterCipher(IdentityCipher.Identifier, typeof(IdentityCipher));
            RegisterCipher(AesGcmCipher.Identifier, typeof(AesGcmCipher));
            RegisterCipher(ChaChaCipher.Identifier, typeof(ChaChaCipher));

            RegisterKeyExchange(EcdhKeyExchange.Identifier, typeof(EcdhKeyExchange));

            RegisterMAC(HMACSHA.Identifier, typeof(HMACSHA));
            RegisterMAC(IdentityMAC.Identifier, typeof(IdentityMAC));

            Initialized = true;
        }
    }
}
