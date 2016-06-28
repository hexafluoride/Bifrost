# CertManager
CertManager is the tool used to generate certificates and certificate authorities for Bifrost.

## Using CertManager
Here's an example workflow:

```
$ certmanager --action generate-ca --ca test
Generating new RSA-2048 keypair...
Wrote 451 bytes to "test.ca".
Wrote 1679 bytes to "test.privkey".
CertManager done. Exiting...

$ certmanager --action generate-key --ca test --key client
Importing certificate authority from "test.privkey"...done.
Generating new RSA-2048 keypair...
Signing keypair...
Saving keypair and signature...
Wrote 1679 bytes to "client.privkey".
Wrote 451 bytes to "client.pub".
Wrote 256 bytes to "client.sign".
Verifying signature...
CertManager done. Exiting...

$ ls
Bifrost.dll  BouncyCastle.Crypto.dll  CertManager.exe  NLog.dll  
client.privkey  client.pub  client.sign  test.ca  test.privkey
```

## Actions

### generate-ca
Generates a new CA. Outputs two files.

|Filename|Contents|
|---|---|
|`<ca-name>.ca`|The public key of the generated certificate authority.|
|`<ca-name>.privkey`|Both the public and the private key of the generated certificate authority.|

### generate-key
Generates a new keypair using an existing CA. You will need to provide a `<ca-name>.privkey` file. Outputs three files.

|Filename|Contents|
|---|---|
|`<key-name>.pub`|The public key of the generated keypair.|
|`<key-name>.privkey`|Both the public and the private key of the generated keypair.|
|`<key-name>.sign`|Signature of the public key, signed by the CA.|

### sign-key
Signs an already existing keypair using an existing CA. You will need to provide the `<key-name>.pub` and `<ca-name>.privkey` files. Outputs one file.

|Filename|Contents|
|---|---|
|`<key-name>.sign`|Signature of the public key, signed by the CA.|

## Help page
```
Usage: certmanager --action generate-ca|generate-key|sign-key --ca-path /path/to/ca [OPTIONS]
Generates and signs certificates for use with Bifrost.

      --action=VALUE         Sets the action.
      --ca, --ca-path=VALUE  Sets the certificate authority file name.
  -k, --key, --key-name=VALUE
                             Sets the key file name(also used for signature
                               file paths).
  -?, -h, --help             Shows help.
```
