# CipherCracker

CipherCracker is a dotnet 8 library that implements common encryption and decryption algorithms.

## Installation

You can install CipherCracker via NuGet package manager:

```bash
dotnet add package CipherCracker
```

## Usage

You can reference the CipherCracker.ClassLibrary namespace in your code, initiate different cryptography manager class to perform encryption and decryption operations. For example:
```c#
Using CipherCracker.ClassLibrary;

var aesKeyBytes = CryptoUtils.GenerateRandomBytes(32);    //AES-256-GCM
var aesGcmManager = new AesGcmManager(aesKeyBytes);

var plainText = "Inhale confidence, exhale doubt.";
var ivBytes = CryptoUtils.GenerateIvBytes();

var encryptedContentBytes = aesGcmManager.Encrypt(Encoding.UTF8.GetBytes(plainText), ivBytes);

var decryptedContentBytes = aesGcmManager.Decrypt(encryptedContentBytes, ivBytes);
```

## Supported algorithms

CipherCracker currently supports the following encryption and decryption algorithms:

* AES (GCM only, at the moment)

## Contribution

Any suggestions or feedback are welcome, or you can submit a pull request to improve the code.

## License

CipherCracker uses the MIT license, please see the LICENSE file for details.