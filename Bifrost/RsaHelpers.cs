using System;
using System.Text;
using System.Linq;
using System.Xml.Linq;
using System.Security.Cryptography;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;

namespace Bifrost
{
    public class RsaHelpers
    {
        /// <summary>
        /// Serializes an object using PEM and returns the serialized data.
        /// </summary>
        /// <param name="obj">The object to be serialized.</param>
        /// <returns>The serialized data.</returns>
        public static string PemSerialize(object obj)
        {
            StringWriter sw = new StringWriter();
            PemWriter pem = new PemWriter(sw);

            pem.WriteObject(obj);
            return sw.ToString();
        }

        /// <summary>
        /// Deserializes a PEM-serialized object.
        /// </summary>
        /// <param name="str">The PEM data to deserialize.</param>
        /// <returns>The deserialized object.</returns>
        public static object PemDeserialize(string str)
        {
            StringReader sr = new StringReader(str);
            PemReader pem = new PemReader(sr);

            return pem.ReadObject();
        }

        /// <summary>
        /// Signs data using SHA256 and RSA.
        /// </summary>
        /// <param name="data">The data to be signed.</param>
        /// <param name="cert">The RSA keypair(only the private key is checked).</param>
        /// <returns>The calculated signature.</returns>
        public static byte[] SignData(byte[] data, AsymmetricCipherKeyPair cert)
        {
            ISigner sig = SignerUtilities.GetSigner("SHA256withRSA");

            sig.Init(true, cert.Private);
            sig.BlockUpdate(data, 0, data.Length);

            return sig.GenerateSignature();
        }

        /// <summary>
        /// Signs data using SHA256 and RSA.
        /// </summary>
        /// <param name="data">The data to be signed.</param>
        /// <param name="cert">The RSA keypair in serialized form.</param>
        /// <returns>The calculated signature.</returns>
        public static byte[] SignData(byte[] data, byte[] cert)
        {
            return SignData(data, (AsymmetricCipherKeyPair)PemDeserialize(Encoding.UTF8.GetString(cert)));
        }

        /// <summary>
        /// Verifies a signature.
        /// </summary>
        /// <param name="data">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="cert">The RSA public key from the keypair that was used to sign the message.</param>
        /// <returns>true if the signature is correct, false otherwise.</returns>
        public static bool VerifyData(byte[] data, byte[] signature, AsymmetricCipherKeyPair cert)
        {
            return VerifyData(data, signature, (RsaKeyParameters)cert.Public);
        }

        /// <summary>
        /// Verifies a signature.
        /// </summary>
        /// <param name="data">The data that was signed.</param>
        /// <param name="signature">The signature to verify.</param>
        /// <param name="pub">The RSA public key from the keypair that was used to sign the message.</param>
        /// <returns>true if the signature is correct, false otherwise.</returns>
        public static bool VerifyData(byte[] data, byte[] signature, RsaKeyParameters pub)
        {
            ISigner sig = SignerUtilities.GetSigner("SHA256withRSA");

            sig.Init(false, pub);
            sig.BlockUpdate(data, 0, data.Length);

            return sig.VerifySignature(signature);
        }

        /// <summary>
        /// Returns an RSACryptoServiceProvider from a string.
        /// </summary>
        /// <param name="text">The string to deserialize the RSACryptoServiceProvider from.</param>
        /// <returns>The deserialized RSACryptoServiceProvider.</returns>
        [Obsolete("The System.Security.Cryptography API is no longer used.")]
        public static RSACryptoServiceProvider LoadFromString(string text)
        {
            XDocument doc = XDocument.Parse(text);

            var data = doc.Descendants("RSAKeyValue").First();

            RSAParameters parameters = new RSAParameters();

            parameters.Modulus = Convert.FromBase64String(data.Element("Modulus").Value);
            parameters.Exponent = Convert.FromBase64String(data.Element("Exponent").Value);

            if (data.Elements("P").Any())
                parameters.P = Convert.FromBase64String(data.Element("P").Value);
            
            if (data.Elements("D").Any())
                parameters.D = Convert.FromBase64String(data.Element("D").Value);
            
            if (data.Elements("DP").Any())
                parameters.DP = Convert.FromBase64String(data.Element("DP").Value);
            
            if (data.Elements("DQ").Any())
                parameters.DQ = Convert.FromBase64String(data.Element("DQ").Value);

            if (data.Elements("Q").Any())
                parameters.Q = Convert.FromBase64String(data.Element("Q").Value);

            if (data.Elements("InverseQ").Any())
                parameters.InverseQ = Convert.FromBase64String(data.Element("InverseQ").Value);

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(parameters);

            return rsa;
        }
    }
}

