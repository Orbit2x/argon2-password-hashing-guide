# Argon2 Password Hashing - Complete Implementation Guide

[![Argon2 Hash Generator](https://img.shields.io/badge/Try%20Online-Argon2%20Generator-blue)](https://orbit2x.com/argon2-generator)
[![OWASP Recommended](https://img.shields.io/badge/OWASP-Recommended-green)](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
[![NIST Compliant](https://img.shields.io/badge/NIST-Compliant-orange)](https://pages.nist.gov/800-63-3/sp800-63b.html)

> **Want to hash passwords without writing code?** Try the free [Argon2 Hash Generator](https://orbit2x.com/argon2-generator) - no installation required, runs in your browser.

## Why Argon2?

Argon2 is the **winner of the Password Hashing Competition** (2015) and is recommended by **OWASP**, **NIST**, and security experts worldwide for password storage.

### Argon2 vs Alternatives

| Algorithm | Year | GPU Resistant | Memory Hard | OWASP Recommended | Security Rating |
|-----------|------|---------------|-------------|-------------------|-----------------|
| **Argon2id** | 2015 | ✅ Yes | ✅ Yes | ✅ Yes | ⭐⭐⭐⭐⭐ (Best) |
| bcrypt | 2009 | ⚠️ Partial | ❌ No | ✅ Yes | ⭐⭐⭐⭐ (Good) |
| PBKDF2 | 2000 | ❌ No | ❌ No | ✅ Yes | ⭐⭐⭐ (Acceptable) |
| scrypt | 2009 | ✅ Yes | ✅ Yes | ✅ Yes | ⭐⭐⭐⭐ (Good) |
| SHA-256 | 2001 | ❌ No | ❌ No | ❌ No | ⭐ (Insecure) |
| MD5 | 1992 | ❌ No | ❌ No | ❌ No | ☠️ (Broken) |

## Quick Start - Hash a Password Online

**Don't want to install libraries?** Use the free online tool:

👉 **[Argon2 Hash Generator at Orbit2x](https://orbit2x.com/argon2-generator)**

Features:
- ✅ OWASP recommended defaults (64MB memory, 3 iterations)
- ✅ Argon2id and Argon2i support
- ✅ PHC string format output
- ✅ Hash verification
- ✅ 100% client-side (no server upload)
- ✅ Free, no signup required

---

## Implementation Examples

### Node.js (argon2 package)

```bash
npm install argon2
```

```javascript
const argon2 = require('argon2');

// Hash a password with OWASP recommended settings
async function hashPassword(password) {
  try {
    const hash = await argon2.hash(password, {
      type: argon2.argon2id,     // Hybrid mode (recommended)
      memoryCost: 65536,          // 64 MB
      timeCost: 3,                // 3 iterations
      parallelism: 4              // 4 threads
    });

    console.log('Hash:', hash);
    // Output: $argon2id$v=19$m=65536,t=3,p=4$...

    return hash;
  } catch (err) {
    console.error('Hashing error:', err);
  }
}

// Verify password
async function verifyPassword(hash, password) {
  try {
    const isValid = await argon2.verify(hash, password);
    console.log('Password valid:', isValid);
    return isValid;
  } catch (err) {
    console.error('Verification error:', err);
    return false;
  }
}

// Usage
(async () => {
  const hash = await hashPassword('MySecurePassword123!');
  await verifyPassword(hash, 'MySecurePassword123!');  // true
  await verifyPassword(hash, 'WrongPassword');         // false
})();
```

### Python (argon2-cffi package)

```bash
pip install argon2-cffi
```

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Create hasher with OWASP recommended parameters
ph = PasswordHasher(
    time_cost=3,        # 3 iterations
    memory_cost=65536,  # 64 MB
    parallelism=4,      # 4 threads
    hash_len=32,        # 32 bytes output
    salt_len=16         # 16 bytes salt
)

# Hash password
password = "MySecurePassword123!"
hash = ph.hash(password)
print(f"Hash: {hash}")
# Output: $argon2id$v=19$m=65536,t=3,p=4$...

# Verify password
try:
    ph.verify(hash, password)
    print("✅ Password valid!")

    # Check if rehashing needed (parameters changed)
    if ph.check_needs_rehash(hash):
        new_hash = ph.hash(password)
        print("⚠️ Rehashing recommended")
except VerifyMismatchError:
    print("❌ Invalid password")
```

### PHP (password_hash with Argon2)

```php
<?php
// PHP 7.2+ with Argon2 support

// Hash password
$password = "MySecurePassword123!";
$hash = password_hash($password, PASSWORD_ARGON2ID, [
    'memory_cost' => 65536,  // 64 MB
    'time_cost'   => 3,       // 3 iterations
    'threads'     => 4        // 4 threads
]);

echo "Hash: " . $hash . "\n";
// Output: $argon2id$v=19$m=65536,t=3,p=4$...

// Verify password
if (password_verify($password, $hash)) {
    echo "✅ Password valid!\n";

    // Check if rehashing needed
    if (password_needs_rehash($hash, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536,
        'time_cost'   => 3,
        'threads'     => 4
    ])) {
        $new_hash = password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost'   => 3,
            'threads'     => 4
        ]);
        echo "⚠️ Rehashing recommended\n";
    }
} else {
    echo "❌ Invalid password\n";
}
?>
```

### Go (golang.org/x/crypto/argon2)

```bash
go get golang.org/x/crypto/argon2
```

```go
package main

import (
    "crypto/rand"
    "crypto/subtle"
    "encoding/base64"
    "fmt"
    "strings"

    "golang.org/x/crypto/argon2"
)

type ArgonParams struct {
    Memory      uint32
    Iterations  uint32
    Parallelism uint8
    SaltLength  uint32
    KeyLength   uint32
}

// OWASP recommended defaults
var DefaultParams = &ArgonParams{
    Memory:      64 * 1024, // 64 MB
    Iterations:  3,
    Parallelism: 4,
    SaltLength:  16,
    KeyLength:   32,
}

func HashPassword(password string, params *ArgonParams) (string, error) {
    // Generate random salt
    salt := make([]byte, params.SaltLength)
    if _, err := rand.Read(salt); err != nil {
        return "", err
    }

    // Hash password
    hash := argon2.IDKey(
        []byte(password),
        salt,
        params.Iterations,
        params.Memory,
        params.Parallelism,
        params.KeyLength,
    )

    // Encode to PHC format
    b64Salt := base64.RawStdEncoding.EncodeToString(salt)
    b64Hash := base64.RawStdEncoding.EncodeToString(hash)

    encodedHash := fmt.Sprintf(
        "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
        argon2.Version,
        params.Memory,
        params.Iterations,
        params.Parallelism,
        b64Salt,
        b64Hash,
    )

    return encodedHash, nil
}

func VerifyPassword(password, encodedHash string) (bool, error) {
    // Parse PHC format
    parts := strings.Split(encodedHash, "$")
    if len(parts) != 6 {
        return false, fmt.Errorf("invalid hash format")
    }

    var memory, iterations uint32
    var parallelism uint8
    _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
    if err != nil {
        return false, err
    }

    salt, err := base64.RawStdEncoding.DecodeString(parts[4])
    if err != nil {
        return false, err
    }

    hash, err := base64.RawStdEncoding.DecodeString(parts[5])
    if err != nil {
        return false, err
    }

    // Hash input password with same parameters
    comparisonHash := argon2.IDKey(
        []byte(password),
        salt,
        iterations,
        memory,
        parallelism,
        uint32(len(hash)),
    )

    // Constant-time comparison
    return subtle.ConstantTimeCompare(hash, comparisonHash) == 1, nil
}

func main() {
    password := "MySecurePassword123!"

    // Hash password
    hash, err := HashPassword(password, DefaultParams)
    if err != nil {
        panic(err)
    }
    fmt.Println("Hash:", hash)

    // Verify correct password
    valid, err := VerifyPassword(password, hash)
    if err != nil {
        panic(err)
    }
    fmt.Println("✅ Password valid:", valid) // true

    // Verify wrong password
    valid, _ = VerifyPassword("WrongPassword", hash)
    fmt.Println("❌ Wrong password:", valid) // false
}
```

---

## OWASP Recommended Parameters (2024)

| Security Level | Memory Cost | Time Cost | Parallelism | Use Case |
|----------------|-------------|-----------|-------------|----------|
| **Low** (Fast) | 32 MB | 2 | 2 | Development/Testing |
| **Medium** (Standard) | 64 MB | 3 | 4 | Most web applications |
| **High** (Secure) | 128 MB | 4 | 4 | Financial/Healthcare |
| **Paranoid** (Maximum) | 256 MB | 5 | 8 | Government/Military |

**OWASP Default Recommendation**: 64 MB memory, 3 iterations, 4 threads

> **Try different security levels**: Use the [Argon2 Generator](https://orbit2x.com/argon2-generator) to test parameter combinations and see performance impact.

---

## Understanding Argon2 Parameters

### Memory Cost (`m` parameter)
- **Controls memory usage** in kilobytes
- **Higher = More GPU resistant**
- OWASP minimum: 64 MB (65536 KB)
- Recommended: 64-256 MB depending on threat model

### Time Cost (`t` parameter)
- **Number of iterations** through memory
- **Higher = Slower but more secure**
- OWASP minimum: 3 iterations
- Each iteration increases hash time linearly

### Parallelism (`p` parameter)
- **Number of threads** used
- **Higher = Faster on multi-core systems**
- OWASP recommended: 4 threads
- Should match server CPU cores (max 255)

### Salt Length
- **Random value** unique per password
- **Prevents rainbow table attacks**
- Recommended: 16 bytes (128 bits)
- Auto-generated by libraries

### Key Length
- **Output hash length**
- Recommended: 32 bytes (256 bits)
- Can be 16-128 bytes depending on needs

---

## Security Best Practices

### ✅ DO

1. **Use Argon2id** (hybrid mode) - Resistant to both GPU and side-channel attacks
2. **Use OWASP defaults** - 64 MB memory, 3 iterations, 4 threads
3. **Generate random salts** - Use cryptographically secure random generator
4. **Store full hash string** - Include parameters in PHC format
5. **Use constant-time comparison** - Prevent timing attacks during verification
6. **Rehash on login** - Update to new parameters when needed
7. **Use PHC string format** - Industry standard for storing hashes

### ❌ DON'T

1. **Don't use Argon2i alone** - Use Argon2id instead (hybrid mode)
2. **Don't reuse salts** - Each password needs unique salt
3. **Don't lower memory below 32 MB** - GPU attacks become feasible
4. **Don't use less than 2 iterations** - Reduces security margin
5. **Don't use raw binary hashes** - Store PHC format with parameters
6. **Don't compare hashes with `==`** - Use constant-time comparison
7. **Don't use SHA-256/MD5** - These are NOT password hashing algorithms

---

## PHC String Format Explained

Argon2 outputs in **PHC (Password Hashing Competition) string format**:

```
$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$hash_output_base64
│    │     │   │              │            │
│    │     │   │              │            └─ Hash output (base64)
│    │     │   │              └─ Salt (base64)
│    │     │   └─ Parameters (memory, time, parallelism)
│    │     └─ Argon2 version (19 = latest)
│    └─ Algorithm variant (id = hybrid)
└─ Algorithm identifier
```

**Benefits of PHC format**:
- ✅ Self-contained (includes all parameters)
- ✅ Forward compatible (version field)
- ✅ Easy to verify (no separate storage)
- ✅ Industry standard

---

## Performance Benchmarks

Tested on Intel i7-10700K (8 cores, 16 threads):

| Memory | Iterations | Threads | Hash Time | Hashes/sec | Security Level |
|--------|-----------|---------|-----------|------------|----------------|
| 32 MB  | 2 | 2 | ~100ms | 10/sec | ⚠️ Low |
| 64 MB  | 3 | 4 | ~200ms | 5/sec | ✅ Standard |
| 128 MB | 4 | 4 | ~400ms | 2.5/sec | 🔒 High |
| 256 MB | 5 | 8 | ~800ms | 1.25/sec | 🛡️ Maximum |

**Rule of thumb**: Hash time should be **250-500ms** to balance security vs user experience.

> **Test your server's performance**: Use the [Argon2 Generator](https://orbit2x.com/argon2-generator) to benchmark different parameters in your browser.

---

## Common Mistakes & How to Fix Them

### Mistake 1: Using bcrypt/PBKDF2 for new projects

**Problem**: Older algorithms are less resistant to GPU attacks

**Fix**:
```javascript
// ❌ DON'T use bcrypt for new projects
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 12);

// ✅ DO use Argon2id
const argon2 = require('argon2');
const hash = await argon2.hash(password, { type: argon2.argon2id });
```

### Mistake 2: Lowering parameters for performance

**Problem**: Weak parameters make hashes vulnerable

**Fix**: Use caching/sessions instead of re-hashing frequently
```javascript
// ❌ DON'T lower parameters
const hash = await argon2.hash(password, { memoryCost: 4096, timeCost: 1 });

// ✅ DO use OWASP defaults + caching
const hash = await argon2.hash(password, { memoryCost: 65536, timeCost: 3 });
// Then cache user session for 24 hours
```

### Mistake 3: Not storing parameters with hash

**Problem**: Can't verify hash without knowing parameters

**Fix**: Use PHC string format (automatic in modern libraries)
```python
# ❌ DON'T store only hash
hash_only = hashlib.sha256(password.encode()).hexdigest()

# ✅ DO use PHC format (includes parameters)
from argon2 import PasswordHasher
ph = PasswordHasher()
phc_hash = ph.hash(password)
# $argon2id$v=19$m=65536,t=3,p=4$salt$hash
```

### Mistake 4: Using same salt for multiple passwords

**Problem**: Rainbow table attacks, pattern detection

**Fix**: Auto-generate unique salt per password (libraries do this automatically)
```go
// ❌ DON'T reuse salt
salt := []byte("static_salt")
hash1 := argon2.IDKey([]byte(password1), salt, 3, 65536, 4, 32)
hash2 := argon2.IDKey([]byte(password2), salt, 3, 65536, 4, 32)

// ✅ DO generate random salt
salt1 := make([]byte, 16)
rand.Read(salt1)
hash1 := argon2.IDKey([]byte(password1), salt1, 3, 65536, 4, 32)

salt2 := make([]byte, 16)
rand.Read(salt2)
hash2 := argon2.IDKey([]byte(password2), salt2, 3, 65536, 4, 32)
```

---

## Tools & Resources

### Online Tools
- **[Argon2 Hash Generator](https://orbit2x.com/argon2-generator)** - Free online Argon2 hash generator with verification
- **[PBKDF2 Generator](https://orbit2x.com/pbkdf2-generator)** - Alternative password hashing (OWASP compliant)
- **[Hash Generator](https://orbit2x.com/hash)** - MD5/SHA-256 for file verification (NOT for passwords)

### Libraries
- **Node.js**: [argon2](https://www.npmjs.com/package/argon2) - C++ bindings, fastest implementation
- **Python**: [argon2-cffi](https://pypi.org/project/argon2-cffi/) - Pure Python with C acceleration
- **PHP**: Built-in `password_hash()` with `PASSWORD_ARGON2ID` (PHP 7.2+)
- **Go**: [golang.org/x/crypto/argon2](https://pkg.go.dev/golang.org/x/crypto/argon2) - Official Go implementation
- **Rust**: [argon2](https://crates.io/crates/argon2) - Pure Rust implementation
- **Java**: [Bouncy Castle](https://www.bouncycastle.org/) - JCE provider with Argon2

### References
- **[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)**
- **[NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)** - Digital Identity Guidelines
- **[Argon2 RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106)** - Official specification
- **[Password Hashing Competition](https://www.password-hashing.net/)** - Background on why Argon2 won

---

## FAQ

### Q: Should I use Argon2i or Argon2id?
**A**: Use **Argon2id** (hybrid mode). It combines the benefits of Argon2i (side-channel resistance) and Argon2d (GPU resistance).

### Q: Can I migrate from bcrypt to Argon2?
**A**: Yes! Re-hash passwords on next login:
```javascript
if (hash.startsWith('$2b$')) {
    // Old bcrypt hash
    if (await bcrypt.compare(password, hash)) {
        // Valid password - rehash with Argon2
        const newHash = await argon2.hash(password);
        // Update database with newHash
    }
} else {
    // Already Argon2
    await argon2.verify(hash, password);
}
```

### Q: How do I tune parameters for my server?
**A**: Target **250-500ms hash time**:
1. Start with OWASP defaults (64 MB, 3 iterations)
2. Measure hash time on your production server
3. Adjust memory cost up/down to hit target time
4. Test the configuration: [Argon2 Generator](https://orbit2x.com/argon2-generator)

### Q: Is Argon2 quantum-resistant?
**A**: No password hashing algorithm is quantum-resistant. However, Argon2's memory-hardness makes it **more expensive to attack with quantum computers** than alternatives.

### Q: Can I use this for API keys?
**A**: No. Use HMAC-SHA256 or Ed25519 signatures for API keys. Password hashing is designed to be **slow** (bad for APIs).

---

## License

This guide is MIT licensed. Code examples are public domain.

## Contributing

Found an error? Have a better example? Open an issue or PR!

## Related Tools

- **[JWT Decoder](https://orbit2x.com/jwt-decoder)** - Decode and inspect JSON Web Tokens
- **[OpenSSL Command Generator](https://orbit2x.com/openssl-command-generator)** - Generate secure OpenSSL commands
- **[Hash Generator](https://orbit2x.com/hash)** - MD5/SHA-256 for file verification
- **[All Developer Tools](https://orbit2x.com/tools)** - 130+ free online tools

---

**Made with ❤️ by [Orbit2x](https://orbit2x.com) - Free Developer Tools**
