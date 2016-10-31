using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

using NDesk.Options;

using Bifrost;

namespace CertManager
{
    class Program
    {
        static void Main(string[] args)
        {
            string action = "";

            string ca_path = "";
            string key_name = "";

            Utilities.LogVersion();

            OptionSet set = new OptionSet();
            set = new OptionSet()
            {
                {"action=", "Sets the action.", a => action = a.ToLower() },
                {"ca|ca-path=", "Sets the certificate authority file name.", c => ca_path = c },
                {"k|key|key-name=", "Sets the key file name(also used for signature file paths).", k => key_name = k },
                {"?|h|help", "Shows help.", h => ShowHelp(set) }
            };
            set.Parse(args);

            if (string.IsNullOrWhiteSpace(ca_path) && (action == "generate-ca" || action == "sign-key"))
            {
                Console.WriteLine("You have to specify a valid filename using --ca when using {0}!", action);
                Console.WriteLine("Try certmanager --help for more info.");

                return;
            }

            if (string.IsNullOrWhiteSpace(key_name) && (action == "generate-key" || action == "sign-key"))
            {
                Console.WriteLine("You have to specify a valid key name using --key-name when using {0}!", action);
                Console.WriteLine("Try certmanager --help for more info.");

                return;
            }
            AsymmetricCipherKeyPair Pair = null;

            if (action == "sign-key")
            {
                if (!File.Exists(ca_path))
                {
                    ca_path += ".privkey";

                    if (!File.Exists(ca_path))
                    {
                        Console.WriteLine("Invalid file path \"{0}\".", ca_path);
                        return;
                    }
                }

                Console.Write("Importing certificate authority from \"{0}\"...", ca_path);
                string pubkey = File.ReadAllText(ca_path);

                var pair = RsaHelpers.PemDeserialize(pubkey);
                Console.WriteLine("done.");

                if (pair is AsymmetricKeyParameter)
                {
                    Console.WriteLine("The certificate authority file you have specified only contains the public key. When using sign-key, you have to use the .privkey file, not the .ca file.");
                    Console.WriteLine("Exiting.");
                    return;
                }

                Pair = (AsymmetricCipherKeyPair)pair;
            }

            switch (action)
            {
                case "generate-ca":
                    {
                        Console.WriteLine("Generating new RSA-2048 keypair...");
                        var CertificateAuthority = new RSACryptoServiceProvider(2048);

                        var parameters = CertificateAuthority.ExportParameters(true);
                        var pair = DotNetUtilities.GetRsaKeyPair(parameters);

                        WriteFile(string.Format("{0}.ca", ca_path), RsaHelpers.PemSerialize(pair.Public));
                        WriteFile(string.Format("{0}.privkey", ca_path), RsaHelpers.PemSerialize(pair));
                        break;
                    }
                case "generate-key":
                    {
                        Console.WriteLine("Generating new RSA-2048 keypair...");
                        var key = new RSACryptoServiceProvider(2048);
                        var parameters = key.ExportParameters(true);
                        var pair = DotNetUtilities.GetRsaKeyPair(parameters);

                        string pub = RsaHelpers.PemSerialize(pair.Public);
                        string priv = RsaHelpers.PemSerialize(pair);

                        Console.WriteLine("Saving keypair...");
                        WriteFile(string.Format("{0}.privkey", key_name), priv);
                        WriteFile(string.Format("{0}.pub", key_name), pub);

                        if (Pair != null)
                        {
                            Console.WriteLine("Signing keypair...");
                            var signature = RsaHelpers.SignData(Encoding.UTF8.GetBytes(pub), Pair);
                            WriteFile(string.Format("{0}.sign", key_name), signature);

                            Console.WriteLine("Verifying signature...");

                            if (!RsaHelpers.VerifyData(Encoding.UTF8.GetBytes(pub), signature, Pair))
                                Console.WriteLine("Failed!");
                        }
                        break;
                    }
                case "sign-key":
                    {
                        if (!File.Exists(key_name))
                        {
                            key_name += ".pub";
                            if (!File.Exists(key_name))
                            {
                                Console.WriteLine("Invalid file path \"{0}\".", key_name);
                                return;
                            }
                        }

                        Console.WriteLine("Reading public key from \"{0}\"...", key_name);
                        string pub = File.ReadAllText(key_name);

                        Console.WriteLine("Signing key...");
                        var signature = RsaHelpers.SignData(Encoding.UTF8.GetBytes(pub), Pair);

                        Console.WriteLine("Saving signature...");

                        if (key_name.Split('/', '\\').Last().Contains("."))
                        {
                            key_name = string.Join(".", key_name.Split('.').Where(str => !key_name.EndsWith(str)));
                        }
                        key_name += ".sign";

                        WriteFile(key_name, signature);
                        break;
                    }
                default:
                    ShowHelp(set);
                    break;
            }

            Console.WriteLine("CertManager done. Exiting...");
        }

        static void WriteFile(string path, byte[] data)
        {
            File.WriteAllBytes(path, data);

            Console.WriteLine("Wrote {0} bytes to \"{1}\".", data.Length, path);
        }

        static void WriteFile(string path, string contents)
        {
            WriteFile(path, Encoding.UTF8.GetBytes(contents));
        }

        static void ShowHelp(OptionSet set)
        {
            Console.WriteLine();
            Console.WriteLine("Usage: certmanager --action generate-ca|generate-key|sign-key --ca-path /path/to/ca [OPTIONS]");
            Console.WriteLine("Generates and signs certificates for use with Bifrost.");
            Console.WriteLine();
            set.WriteOptionDescriptions(Console.Out);
        }
    }
}
