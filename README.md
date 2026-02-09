# Corp.Lib.Cryptography

A .NET 10 cryptographic library for encrypting, decrypting, and hashing data.

[![NuGet](https://img.shields.io/nuget/v/Corp.Lib.Cryptography.svg)](https://www.nuget.org/packages/Corp.Lib.Cryptography/)

## Installation

```bash
dotnet add package Corp.Lib.Cryptography
```

## Environment Variables

| Variable | Description | Used By |
|----------|-------------|---------|
| `encryption_string` | AES-128 encryption password | `Aes.Encrypt()`, `Aes.Decrypt()` |
| `strongencryption_string` | AES-256 encryption password | `Aes.StrongEncrypt()`, `Aes.StrongDecrypt()` |
| `knownsecret_string` | Argon2 known secret | `Argon2.Hash()`, `Argon2.CompareHashes()` |

> **Note:** `AesGcmFile` does **not** use environment variables. Passwords are passed directly to methods.

---

## Aes Class

String encryption using AES-128 or AES-256. Keys derived from environment variables.

```csharp
using Corp.Lib.Cryptography;

// AES-128
string encrypted = Aes.Encrypt("sensitive data");
string decrypted = Aes.Decrypt(encrypted);

// AES-256
string strongEncrypted = Aes.StrongEncrypt("sensitive data");
string strongDecrypted = Aes.StrongDecrypt(strongEncrypted);
```

---

## AesGcmFile Class

File encryption using AES-256 GCM with PCI DSS 4.0 compliant key versioning.

**Features:**
- AES-256 GCM authenticated encryption
- Key version stored in file header for rotation support
- Automatic chunking for files > 250MB
- Passwords passed directly to methods (no environment variables)

### Encrypt

```csharp
await AesGcmFile.EncryptFileAsync(
    sourceFilePath: "document.pdf",
    destinationFilePath: "document.pdf.enc",
    password: "your-secret-password",
    keyVersion: 1);
```

### Decrypt (single password)

```csharp
await AesGcmFile.DecryptFileAsync(
    sourceFilePath: "document.pdf.enc",
    destinationFilePath: "document.pdf",
    password: "your-secret-password");
```

### Decrypt (with key rotation support)

```csharp
await AesGcmFile.DecryptFileAsync(
    sourceFilePath: "document.pdf.enc",
    destinationFilePath: "document.pdf",
    passwordProvider: version => version switch
    {
        1 => "old-password",
        2 => "new-password",
        _ => null
    });
```

### Check key version

```csharp
int version = await AesGcmFile.GetFileKeyVersionAsync("document.pdf.enc");
```

### Re-encrypt after key rotation

```csharp
int oldVersion = await AesGcmFile.ReEncryptFileAsync(
    encryptedFilePath: "document.pdf.enc",
    newPassword: "new-password",
    newKeyVersion: 2,
    passwordProvider: v => v == 1 ? "old-password" : null);
```

### API Reference

| Method | Description |
|--------|-------------|
| `EncryptFileAsync(source, dest, password, keyVersion, ct)` | Encrypt file with password and key version |
| `DecryptFileAsync(source, dest, password, ct)` | Decrypt file with single password |
| `DecryptFileAsync(source, dest, passwordProvider, ct)` | Decrypt file with versioned password lookup |
| `GetFileKeyVersionAsync(filePath, ct)` | Get key version from encrypted file header |
| `ReEncryptFileAsync(path, newPassword, newKeyVersion, passwordProvider, ct)` | Re-encrypt with new key version |

### Technical Specs

| Property | Value |
|----------|-------|
| Algorithm | AES-256 GCM |
| Key Derivation | PBKDF2-SHA256 (100,000 iterations) |
| Nonce | 96 bits (unique per chunk) |
| Auth Tag | 128 bits |
| Chunk Size | 50 MB (for files > 250 MB) |

---

## Argon2 Class

Password hashing using Argon2id.

### Hash a password

```csharp
string hash = Argon2.Hash("user-password", out string salt);
// Store both hash and salt in database
```

### Verify a password

```csharp
bool isValid = Argon2.CompareHashes("user-input", storedHash, storedSalt);
```

---

## Rijndael Class (Legacy)

> **Deprecated** - Use `Aes` class instead. Provided only for backward compatibility.

```csharp
// Don't use for new code
string encrypted = Rijndael.Encrypt("data");
string decrypted = Rijndael.Decrypt(encrypted);
```

---

## Key Rotation Workflow (PCI DSS 4.0)

```csharp
// 1. Define password provider with all versions
Func<int, string?> passwords = version => version switch
{
    1 => "password-v1",
    2 => "password-v2",
    _ => null
};

// 2. Find and rotate files
foreach (var file in Directory.GetFiles(folder, "*.enc"))
{
    int version = await AesGcmFile.GetFileKeyVersionAsync(file);
    
    if (version < 2)
    {
        await AesGcmFile.ReEncryptFileAsync(file, "password-v2", 2, passwords);
    }
}
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography/) | Cryptographic primitives |
| [Konscious.Security.Cryptography.Argon2](https://www.nuget.org/packages/Konscious.Security.Cryptography.Argon2/) | Argon2id implementation |

---

## License

Copyright © Sedgwick Consumer Claims. All rights reserved.
