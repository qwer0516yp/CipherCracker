﻿namespace CipherCracker.ClassLibrary;

public interface IAesGcmManager
{
    string EncryptBlockBase64(string plainText, bool isIv12NullBytes, out string ivBase64);
    string DecryptBlockBase64(string encryptedBlockBase64, string ivBase64);
}
