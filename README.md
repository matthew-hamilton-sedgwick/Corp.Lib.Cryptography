# Corp.Lib.Cryptography

A .NET 10 cryptographic library for encrypting, decrypting, and hashing data. This library provides secure implementations of AES encryption and Argon2 password hashing for the Voyager Application.

[![NuGet](https://img.shields.io/nuget/v/Corp.Lib.Cryptography.svg)](https://www.nuget.org/packages/Corp.Lib.Cryptography/)

## Table of Contents

- [Installation](#installation)
- [Prerequisites](#prerequisites)
- [Environment Variables](#environment-variables)
- [Features](#features)
- [Usage](#usage)
  - [AES Encryption](#aes-encryption)
  - [Argon2 Hashing](#argon2-hashing)
- [Migration Guide](#migration-guide)
- [API Reference](#api-reference)
- [Security Considerations](#security-considerations)
- [Dependencies](#dependencies)
- [License](#license)

## Installation

Install the package via NuGet Package Manager:

```bash
dotnet add package Corp.Lib.Cryptography
```

Or via the Package Manager Console in Visual Studio:

```powershell
Install-Package Corp.Lib.Cryptography
```

## Prerequisites

- **.NET 10** or later
- Environment variables configured (see [Environment Variables](#environment-variables))

## Environment Variables

The library requires the following environment variables to be set before use:

| Variable | Description | Required For |
|----------|-------------|--------------|
| `encryption_string` | Password used for AES 128-bit encryption key derivation | `Aes.Encrypt()`, `Aes.Decrypt()` |
| `strongencryption_string` | Password used for AES 256-bit encryption key derivation | `Aes.StrongEncrypt()`, `Aes.StrongDecrypt()` |
| `knownsecret_string` | Known secret used for Argon2 hashing | `Argon2.Hash()`, `Argon2.CompareHashes()` |

### Setting Environment Variables

**Windows (PowerShell):**
```powershell
$env:encryption_string = "your-encryption-password"
$env:strongencryption_string = "your-strong-encryption-password"
$env:knownsecret_string = "your-known-secret"
```

**Windows (System Environment):**
```cmd
setx encryption_string "your-encryption-password"
setx strongencryption_string "your-strong-encryption-password"
setx knownsecret_string "your-known-secret"
```

**Linux/macOS:**
```bash
export encryption_string="your-encryption-password"
export strongencryption_string="your-strong-encryption-password"
export knownsecret_string="your-known-secret"
```

**Azure App Service / Azure Functions:**
Configure these in the Application Settings section of your Azure resource.

## Features

| Feature | Class | Description |
|---------|-------|-------------|
| AES-128 Encryption | `Aes` | Standard AES encryption with 128-bit key |
| AES-256 Encryption | `Aes` | Strong AES encryption with 256-bit key |
| Argon2id Hashing | `Argon2` | Secure password hashing using Argon2id algorithm |

## Usage

### AES Encryption

#### Standard Encryption (AES-128)

Use for general-purpose encryption needs:

```csharp
using Corp.Lib.Cryptography;

// Encrypt a string
string plainText = "Sensitive data to encrypt";
string encrypted = Aes.Encrypt(plainText);

// Decrypt the string
string decrypted = Aes.Decrypt(encrypted);

Console.WriteLine($"Original: {plainText}");
Console.WriteLine($"Encrypted: {encrypted}");
Console.WriteLine($"Decrypted: {decrypted}");
```

#### Strong Encryption (AES-256)

Use for highly sensitive data requiring stronger encryption:

```csharp
using Corp.Lib.Cryptography;

// Encrypt with AES-256
string sensitiveData = "Highly sensitive information";
string strongEncrypted = Aes.StrongEncrypt(sensitiveData);

// Decrypt with AES-256
string strongDecrypted = Aes.StrongDecrypt(strongEncrypted);

Console.WriteLine($"Original: {sensitiveData}");
Console.WriteLine($"Strong Encrypted: {strongEncrypted}");
Console.WriteLine($"Strong Decrypted: {strongDecrypted}");
```

### Argon2 Hashing

Argon2id is the recommended algorithm for password hashing. It is resistant to GPU-based attacks and side-channel attacks.

#### Hashing a Password

```csharp
using Corp.Lib.Cryptography;

string password = "user-password-123";

// Hash the password - salt is generated automatically
string hashedPassword = Argon2.Hash(password, out string salt);

// Store both hashedPassword and salt in your database
Console.WriteLine($"Hashed Password: {hashedPassword}");
Console.WriteLine($"Salt: {salt}");
```

#### Verifying a Password

```csharp
using Corp.Lib.Cryptography;

string userInput = "user-password-123";
string storedHash = "..."; // Retrieved from database
string storedSalt = "..."; // Retrieved from database

// Compare the user input with the stored hash
bool isValid = Argon2.CompareHashes(userInput, storedHash, storedSalt);

if (isValid)
{
    Console.WriteLine("Password is correct!");
}
else
{
    Console.WriteLine("Invalid password.");
}
```

## Migration Guide

### Migrating from Corp.DAL Encryption

If you're migrating from `Corp.DAL` encryption methods, use the legacy methods during the transition period:

| Old Method (Corp.DAL) | Legacy Method | New Method |
|-----------------------|---------------|------------|
| `Encrypt()` | `Aes.Aes128Encrypt()` | `Aes.Encrypt()` |
| `Decrypt()` | `Aes.Aes128Decrypt()` | `Aes.Decrypt()` |
| `StrongEncrypt()` | `Aes.Aes256Encrypt()` | `Aes.StrongEncrypt()` |
| `StrongDecrypt()` | `Aes.Aes256Decrypt()` | `Aes.StrongDecrypt()` |

> ?? **Note:** The legacy methods (`Aes128Encrypt`, `Aes128Decrypt`, `Aes256Encrypt`, `Aes256Decrypt`) are marked as obsolete and will be removed in a future version. Plan to migrate to the new methods.

### Migrating from Rijndael

The `Rijndael` class is provided for backward compatibility only. **Do not use these methods for new development** as RijndaelManaged is considered cryptographically weak.

```csharp
// ? Do NOT use for new development
string encrypted = Rijndael.Encrypt("data");

// ? Use AES instead
string encrypted = Aes.Encrypt("data");
```

## API Reference

### Aes Class

| Method | Description | Returns |
|--------|-------------|---------|
| `Encrypt(string unencrypted)` | Encrypts using AES-128 | Base64 encoded string |
| `Decrypt(string encrypted)` | Decrypts AES-128 encrypted data | Original string |
| `StrongEncrypt(string unencrypted)` | Encrypts using AES-256 | Base64 encoded string |
| `StrongDecrypt(string encrypted)` | Decrypts AES-256 encrypted data | Original string |

### Argon2 Class

| Method | Description | Returns |
|--------|-------------|---------|
| `Hash(string stringToHash, out string salt)` | Hashes a string with auto-generated salt | Base64 encoded hash |
| `CompareHashes(string stringToHash, string hashToCompare, string salt)` | Compares a string against a hash | `true` if match, `false` otherwise |

## Security Considerations

1. **Environment Variables**: Never commit environment variable values to source control. Use secure secret management solutions like Azure Key Vault, AWS Secrets Manager, or HashiCorp Vault.

2. **Key Rotation**: Plan for periodic rotation of encryption keys. Store the key version with encrypted data to support decryption during rotation.

3. **Salt Storage**: Always store the Argon2 salt alongside the hashed password. The salt is not secret but is required for verification.

4. **Deprecated Methods**: Avoid using obsolete methods (`Rijndael.*`, `Aes128*`, `Aes256*`) in new code. These are maintained only for backward compatibility.

5. **Transport Security**: Always use TLS/HTTPS when transmitting encrypted data over networks.

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| [BouncyCastle.Cryptography](https://www.nuget.org/packages/BouncyCastle.Cryptography/) | 2.6.2 | Post-quantum cryptography support |
| [Konscious.Security.Cryptography.Argon2](https://www.nuget.org/packages/Konscious.Security.Cryptography.Argon2/) | 1.3.1 | Argon2id hashing implementation |

## License

Copyright © Sedgwick Consumer Claims. All rights reserved.

This library is part of the Voyager Application and is intended for internal use only.
