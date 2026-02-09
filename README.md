# Corp.Lib.Cryptography

A .NET 10 cryptographic library providing secure AES encryption, AES-GCM file encryption with PCI DSS 4.0 key versioning, and Argon2id password hashing.

[![NuGet](https://img.shields.io/nuget/v/Corp.Lib.Cryptography.svg)](https://www.nuget.org/packages/Corp.Lib.Cryptography/)

## Installation

```bash
dotnet add package Corp.Lib.Cryptography
```

## Environment Variables

The `Aes` and `Argon2` classes require environment variables for key material. The `AesGcmFile` class does **not** use environment variables—passwords are passed directly to methods for explicit control.

| Variable | Description | Used By |
|----------|-------------|---------|
| `encryption_string` | Password for AES-128 key derivation | `Aes.Encrypt()`, `Aes.Decrypt()` |
| `strongencryption_string` | Password for AES-256 key derivation | `Aes.StrongEncrypt()`, `Aes.StrongDecrypt()` |
| `knownsecret_string` | Known secret combined with user passwords for Argon2 | `Argon2.Hash()`, `Argon2.CompareHashes()` |

---

## Aes Class

Provides symmetric string encryption using AES algorithm. Keys are derived from environment variables using PBKDF2.

### Methods

#### `Encrypt(string unencrypted)`

Encrypts a string using AES-128 (128-bit key).

| Parameter | Type | Description |
|-----------|------|-------------|
| `unencrypted` | `string` | The plaintext string to encrypt |
| **Returns** | `string` | Base64-encoded ciphertext containing IV + encrypted data |

```csharp
string encrypted = Aes.Encrypt("sensitive data");
// Returns: "Base64EncodedCiphertext..."
```

#### `Decrypt(string encrypted)`

Decrypts a string that was encrypted with `Encrypt()`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `encrypted` | `string` | Base64-encoded ciphertext from `Encrypt()` |
| **Returns** | `string` | Original plaintext string |

```csharp
string decrypted = Aes.Decrypt(encrypted);
// Returns: "sensitive data"
```

#### `StrongEncrypt(string unencrypted)`

Encrypts a string using AES-256 (256-bit key) for higher security requirements.

| Parameter | Type | Description |
|-----------|------|-------------|
| `unencrypted` | `string` | The plaintext string to encrypt |
| **Returns** | `string` | Base64-encoded ciphertext containing IV + encrypted data |

```csharp
string encrypted = Aes.StrongEncrypt("highly sensitive data");
```

#### `StrongDecrypt(string encrypted)`

Decrypts a string that was encrypted with `StrongEncrypt()`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `encrypted` | `string` | Base64-encoded ciphertext from `StrongEncrypt()` |
| **Returns** | `string` | Original plaintext string |

```csharp
string decrypted = Aes.StrongDecrypt(encrypted);
```

---

## AesGcmFile Class

Provides file encryption using AES-256 in Galois/Counter Mode (GCM). This class is designed for PCI DSS 4.0 compliance with built-in key versioning to support cryptographic key rotation.

### Key Concepts

- **AES-256 GCM**: An authenticated encryption mode that provides both confidentiality (encryption) and integrity (tamper detection). If any byte of the encrypted file is modified, decryption will fail.
- **Key Versioning**: Each encrypted file stores a key version number in its header. This allows you to rotate encryption keys while still being able to decrypt files encrypted with older keys.
- **Automatic Chunking**: Files larger than 250MB are automatically split into 50MB chunks, each encrypted with a unique nonce. This prevents memory issues with large files.
- **Password-Based**: Passwords are passed directly to methods (not from environment variables) for explicit control over key material.

### Methods

#### `EncryptFileAsync`

Encrypts a file using AES-256 GCM with a specified password and key version.

```csharp
public static async Task EncryptFileAsync(
    string sourceFilePath,
    string destinationFilePath,
    string password,
    int keyVersion,
    CancellationToken cancellationToken = default)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `sourceFilePath` | `string` | Full path to the file you want to encrypt |
| `destinationFilePath` | `string` | Full path where the encrypted file will be written |
| `password` | `string` | The password used for key derivation. Store this securely (e.g., Azure Key Vault) |
| `keyVersion` | `int` | Version number to identify this key (e.g., 1, 2, 3). Stored in file header for future decryption |
| `cancellationToken` | `CancellationToken` | Optional token to cancel long-running operations |

**What happens internally:**
1. The password is combined with a versioned salt and processed through PBKDF2-SHA256 (100,000 iterations) to derive a 256-bit key
2. A 17-byte header is written containing: format version, key version, chunk count, and original file size
3. A random 96-bit nonce is generated
4. The file content is encrypted using AES-256 GCM
5. A 128-bit authentication tag is computed to detect tampering

**Example:**
```csharp
// Encrypt a PDF document
await AesGcmFile.EncryptFileAsync(
    sourceFilePath: @"C:\Documents\contract.pdf",
    destinationFilePath: @"C:\Encrypted\contract.pdf.enc",
    password: "MySecurePassword123!",
    keyVersion: 1);
```

---

#### `DecryptFileAsync` (single password)

Decrypts a file using a single password. Use this when you're not rotating keys or when all your files use the same password.

```csharp
public static Task DecryptFileAsync(
    string sourceFilePath,
    string destinationFilePath,
    string password,
    CancellationToken cancellationToken = default)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `sourceFilePath` | `string` | Full path to the encrypted file |
| `destinationFilePath` | `string` | Full path where the decrypted file will be written |
| `password` | `string` | The same password used during encryption |
| `cancellationToken` | `CancellationToken` | Optional token to cancel long-running operations |

**What happens internally:**
1. Reads the file header to get the key version, chunk count, and original size
2. Derives the same key using the password and key version from the header
3. Verifies the authentication tag to detect tampering
4. Decrypts the content and writes to the destination

**Example:**
```csharp
await AesGcmFile.DecryptFileAsync(
    sourceFilePath: @"C:\Encrypted\contract.pdf.enc",
    destinationFilePath: @"C:\Decrypted\contract.pdf",
    password: "MySecurePassword123!");
```

---

#### `DecryptFileAsync` (with password provider)

Decrypts a file using a password provider function. Use this when you have rotated keys and different files may be encrypted with different key versions.

```csharp
public static async Task DecryptFileAsync(
    string sourceFilePath,
    string destinationFilePath,
    Func<int, string?> passwordProvider,
    CancellationToken cancellationToken = default)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `sourceFilePath` | `string` | Full path to the encrypted file |
| `destinationFilePath` | `string` | Full path where the decrypted file will be written |
| `passwordProvider` | `Func<int, string?>` | A function that receives a key version number and returns the corresponding password. Return `null` if the version is unknown |
| `cancellationToken` | `CancellationToken` | Optional token to cancel long-running operations |

**What happens internally:**
1. Reads the key version from the file header
2. Calls your `passwordProvider` function with that version number
3. Uses the returned password to derive the decryption key
4. Decrypts and verifies the file

**Example:**
```csharp
// Define a function that maps key versions to passwords
Func<int, string?> getPassword = version => version switch
{
    1 => "OldPassword2023",      // Original password (retired)
    2 => "NewPassword2024",      // Current password
    3 => "FuturePassword2025",   // Planned rotation
    _ => null                    // Unknown version
};

await AesGcmFile.DecryptFileAsync(
    sourceFilePath: @"C:\Encrypted\contract.pdf.enc",
    destinationFilePath: @"C:\Decrypted\contract.pdf",
    passwordProvider: getPassword);
```

---

#### `GetFileKeyVersionAsync`

Reads the key version from an encrypted file's header without decrypting the file. Useful for auditing which files need key rotation.

```csharp
public static async Task<int> GetFileKeyVersionAsync(
    string filePath,
    CancellationToken cancellationToken = default)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `filePath` | `string` | Full path to the encrypted file |
| `cancellationToken` | `CancellationToken` | Optional token to cancel the operation |
| **Returns** | `int` | The key version number stored in the file header |

**Example:**
```csharp
int version = await AesGcmFile.GetFileKeyVersionAsync(@"C:\Encrypted\contract.pdf.enc");
Console.WriteLine($"This file was encrypted with key version {version}");

// Use for compliance auditing
foreach (var file in Directory.GetFiles(@"C:\Encrypted", "*.enc"))
{
    int v = await AesGcmFile.GetFileKeyVersionAsync(file);
    if (v < 2) // Current version is 2
    {
        Console.WriteLine($"AUDIT: {file} uses outdated key version {v}");
    }
}
```

---

#### `ReEncryptFileAsync`

Re-encrypts a file with a new password and key version. Use this during key rotation to migrate files from an old key to a new key.

```csharp
public static async Task<int> ReEncryptFileAsync(
    string encryptedFilePath,
    string newPassword,
    int newKeyVersion,
    Func<int, string?> passwordProvider,
    CancellationToken cancellationToken = default)
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `encryptedFilePath` | `string` | Full path to the encrypted file to re-encrypt |
| `newPassword` | `string` | The new password to use for encryption |
| `newKeyVersion` | `int` | The new key version number (must be different from current) |
| `passwordProvider` | `Func<int, string?>` | Function to get the old password for the current key version |
| `cancellationToken` | `CancellationToken` | Optional token to cancel long-running operations |
| **Returns** | `int` | The previous key version that the file was encrypted with |

**What happens internally:**
1. Reads the current key version from the file
2. Validates that the new version is different (throws `InvalidOperationException` if same)
3. Decrypts the file to a secure temporary location using the old password
4. Re-encrypts with the new password and key version
5. Overwrites the original encrypted file
6. Securely deletes the temporary file

**Example:**
```csharp
// Password provider for all historical versions
Func<int, string?> passwords = v => v switch
{
    1 => "Password2023",
    2 => "Password2024",
    _ => null
};

// Re-encrypt a single file
int oldVersion = await AesGcmFile.ReEncryptFileAsync(
    encryptedFilePath: @"C:\Encrypted\contract.pdf.enc",
    newPassword: "Password2025",
    newKeyVersion: 3,
    passwordProvider: passwords);

Console.WriteLine($"Migrated from key version {oldVersion} to version 3");
```

---

### Technical Specifications

| Property | Value | Description |
|----------|-------|-------------|
| Algorithm | AES-256 GCM | Authenticated encryption with associated data (AEAD) |
| Key Size | 256 bits | Provides strong security against brute-force attacks |
| Key Derivation | PBKDF2-SHA256 | 100,000 iterations with versioned salt |
| Nonce Size | 96 bits | Unique per encryption operation; includes chunk index for large files |
| Auth Tag Size | 128 bits | Detects any modification to ciphertext |
| Chunk Threshold | 250 MB | Files larger than this are chunked |
| Chunk Size | 50 MB | Each chunk encrypted independently |

### Encrypted File Format

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 byte | Format Version | Currently `0x02` |
| 1 | 4 bytes | Key Version | Little-endian int32 identifying the encryption key |
| 5 | 4 bytes | Chunk Count | Number of encrypted chunks (1 for files ≤ 250MB) |
| 9 | 8 bytes | Original Size | Original file size in bytes |
| 17 | 12 bytes | Nonce | Random nonce for this chunk |
| 29 | 16 bytes | Auth Tag | GCM authentication tag |
| 45 | varies | Ciphertext | Encrypted file content |

---

## Argon2 Class

Provides password hashing using the Argon2id algorithm, which is resistant to GPU-based and side-channel attacks. Recommended by OWASP for password storage.

### Methods

#### `Hash(string stringToHash, out string salt)`

Hashes a password with an automatically generated random salt.

| Parameter | Type | Description |
|-----------|------|-------------|
| `stringToHash` | `string` | The password to hash |
| `salt` | `out string` | Output parameter that receives the generated salt (Base64-encoded) |
| **Returns** | `string` | The password hash (Base64-encoded) |

**Important:** You must store both the hash AND the salt in your database. The salt is required for verification.

```csharp
string hash = Argon2.Hash("UserPassword123", out string salt);

// Store in database:
// - hash:  "Base64EncodedHash..."
// - salt:  "Base64EncodedSalt..."
```

#### `CompareHashes(string stringToHash, string hashToCompare, string salt)`

Verifies a password against a stored hash.

| Parameter | Type | Description |
|-----------|------|-------------|
| `stringToHash` | `string` | The password attempt to verify |
| `hashToCompare` | `string` | The stored hash from your database |
| `salt` | `string` | The stored salt from your database |
| **Returns** | `bool` | `true` if the password matches, `false` otherwise |

```csharp
// Retrieve from database
string storedHash = "...";
string storedSalt = "...";

// Verify user login
bool isValid = Argon2.CompareHashes("UserPassword123", storedHash, storedSalt);

if (isValid)
    Console.WriteLine("Login successful");
else
    Console.WriteLine("Invalid password");
```

---

## Rijndael Class (Legacy)

> ⚠️ **Deprecated**: This class uses the obsolete `RijndaelManaged` algorithm and exists only for backward compatibility with existing encrypted data. **Do not use for new development.**

Use the `Aes` class instead for all new encryption needs.

```csharp
// ❌ Legacy - don't use for new code
string encrypted = Rijndael.Encrypt("data");
string decrypted = Rijndael.Decrypt(encrypted);

// ✅ Use this instead
string encrypted = Aes.Encrypt("data");
string decrypted = Aes.Decrypt(encrypted);
```

---

## Key Rotation Workflow (PCI DSS 4.0)

PCI DSS 4.0 requires periodic rotation of cryptographic keys. Here's a complete workflow:

```csharp
// Step 1: Define all historical and current passwords
Func<int, string?> passwordProvider = version => version switch
{
    1 => Environment.GetEnvironmentVariable("CRYPTO_KEY_V1"),
    2 => Environment.GetEnvironmentVariable("CRYPTO_KEY_V2"),
    3 => Environment.GetEnvironmentVariable("CRYPTO_KEY_V3"),
    _ => null
};

// Step 2: Get the new password for the target version
string newPassword = Environment.GetEnvironmentVariable("CRYPTO_KEY_V3")!;
int targetVersion = 3;

// Step 3: Audit and rotate all encrypted files
var encryptedFiles = Directory.GetFiles(@"C:\EncryptedData", "*.enc", SearchOption.AllDirectories);

foreach (var file in encryptedFiles)
{
    int currentVersion = await AesGcmFile.GetFileKeyVersionAsync(file);
    
    if (currentVersion < targetVersion)
    {
        Console.WriteLine($"Rotating: {file} (v{currentVersion} -> v{targetVersion})");
        
        int oldVersion = await AesGcmFile.ReEncryptFileAsync(
            file,
            newPassword,
            targetVersion,
            passwordProvider);
            
        Console.WriteLine($"  Completed: migrated from v{oldVersion}");
    }
}

Console.WriteLine("Key rotation complete");
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography/) | Cryptographic algorithm implementations |
| [Konscious.Security.Cryptography.Argon2](https://www.nuget.org/packages/Konscious.Security.Cryptography.Argon2/) | Argon2id password hashing |

---

## License

Copyright © Sedgwick Consumer Claims. All rights reserved.
