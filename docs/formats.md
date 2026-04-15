# Serialization Format Specification

All `mlpki` wire formats use **CBOR** ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949))
with **integer keys** exclusively. No string keys appear anywhere in the
encoding. Timestamps are plain unsigned integers (Unix epoch seconds).
Byte strings are CBOR `bstr` items.

---

## Integer Key Registry

All field numbers used across the library:

### TBSCertificate

| Key | Name | Type | Description |
|---|---|---|---|
| `1` | `version` | uint | Always `1` for this version of the format |
| `2` | `serial` | bstr[16] | Random 16-byte serial number |
| `3` | `issuer` | map | Name sub-map (see below) |
| `4` | `subject` | map | Name sub-map |
| `5` | `not_before` | uint | Validity start (Unix timestamp) |
| `6` | `not_after` | uint | Validity end (Unix timestamp) |
| `7` | `public_key` | map | PublicKeyInfo sub-map |
| `8` | `is_ca` | bool | True for CA certificates |
| `9` | `path_len` | uint \| null | Max intermediate CA depth (`null` = unlimited) |
| `10` | `key_usage` | uint | Bitmask (see Key-Usage Flags) |
| `11` | `subject_key_id` | bstr[16] | SHA3-256(pub_key_bytes)[:16] |
| `12` | `auth_key_id` | bstr[16] | Issuer's subject_key_id |

### Certificate (outer structure)

| Key | Name | Type | Description |
|---|---|---|---|
| `1` | `tbs_bytes` | bstr | CBOR encoding of TBSCertificate |
| `2` | `sig_alg` | uint | Algorithm ID |
| `3` | `signature` | bstr | ML-DSA signature over `tbs_bytes` |

### Name sub-map

| Key | Name | Type | Description |
|---|---|---|---|
| `1` | `cn` | tstr | Common Name |
| `2` | `org` | tstr | Organisation |
| `3` | `ou` | tstr | Organisational Unit (optional) |

### PublicKeyInfo sub-map

| Key | Name | Type | Description |
|---|---|---|---|
| `1` | `alg_id` | uint | Algorithm ID |
| `2` | `key_bytes` | bstr | Raw ML-DSA public key bytes |

### CertificateSigningRequest

| Key | Name | Type | Description |
|---|---|---|---|
| `1` | `version` | uint | Always `1` |
| `2` | `subject` | map | Name sub-map |
| `3` | `public_key` | map | PublicKeyInfo sub-map |
| `4` | `sig_alg` | uint | Algorithm ID |
| `5` | `signature` | bstr | ML-DSA self-signature |
| `6` | `is_ca` | bool | Requested CA extension |
| `7` | `path_len` | uint \| null | Requested path length |
| `8` | `key_usage` | uint | Requested key-usage bitmask |

### RevocationList (CRL)

| Key | Name | Type | Description |
|---|---|---|---|
| `1` | `issuer_key_id` | bstr[16] | Issuer's subject_key_id |
| `2` | `this_update` | uint | CRL issue timestamp |
| `3` | `next_update` | uint | Timestamp of next expected update |
| `4` | `revoked_serials` | array[bstr[16]] | List of revoked serials |
| `5` | `sig_alg` | uint | Algorithm ID |
| `6` | `signature` | bstr | ML-DSA signature over fields 1–5 |

### Encrypted Key File

| Key | Name | Type | Description |
|---|---|---|---|
| `1` | `alg_id` | uint | Algorithm ID of the enclosed key |
| `2` | `argon2_params` | map | Argon2id parameter sub-map |
| `3` | `nonce` | bstr[12] | AES-GCM nonce (random, 12 bytes) |
| `4` | `ciphertext` | bstr | AES-256-GCM encrypted secret key |
| `5` | `tag` | bstr[16] | AES-GCM authentication tag |

#### Argon2id parameter sub-map

| Key | Name | Type | Description |
|---|---|---|---|
| `1` | `time_cost` | uint | Number of iterations |
| `2` | `memory_cost` | uint | Memory in KiB |
| `3` | `parallelism` | uint | Degree of parallelism |
| `4` | `salt` | bstr[16] | Random 16-byte salt |

---

## Algorithm IDs

| ID | Name | Key sizes |
|---|---|---|
| `1` | `ML-DSA-44` | pub 1312 B / sec 2560 B / sig ≤ 2420 B |
| `2` | `ML-DSA-65` | pub 1952 B / sec 4032 B / sig ≤ 3309 B |
| `3` | `ML-DSA-87` | pub 2592 B / sec 4896 B / sig ≤ 4627 B |

---

## Key-Usage Bitmask

| Bit | Constant | Value | Meaning |
|---|---|---|---|
| 0 | `KEY_USAGE_DIGITAL_SIGNATURE` | `0x01` | Signing certificates or data |
| 1 | `KEY_USAGE_KEY_CERT_SIGN` | `0x02` | Must be set on all CA certificates |
| 2 | `KEY_USAGE_CRL_SIGN` | `0x04` | Must be set on CRL issuers |

Multiple bits may be combined: a CA that also signs data would use
`0x01 | 0x02 | 0x04 = 0x07`.

---

## Signature Coverage

### Certificate

The ML-DSA signature covers **only** the raw bytes of the CBOR-encoded
`TBSCertificate` (field `1` of the outer Certificate map). The outer
`sig_alg` and `signature` fields are not included.

```
sig = ML-DSA.Sign(secret_key, cbor_encode(TBSCertificate))
```

### CSR

The ML-DSA self-signature covers the CBOR encoding of the map containing
fields `1, 2, 3, 4, 6, 7, 8` — that is, every field **except** the
signature field (`5`):

```
tbs = cbor_encode({1: version, 2: subject, 3: public_key,
                   4: sig_alg, 6: is_ca, 7: path_len, 8: key_usage})
sig = ML-DSA.Sign(secret_key, tbs)
```

### CRL

The ML-DSA signature covers the CBOR encoding of fields `1–5` (all
fields except `6: signature`):

```
tbs = cbor_encode({1: issuer_key_id, 2: this_update, 3: next_update,
                   4: revoked_serials, 5: sig_alg})
sig = ML-DSA.Sign(secret_key, tbs)
```

---

## File Extensions

| Extension | Format | Content |
|---|---|---|
| `.mlcert` | Binary CBOR | Serialized `Certificate` |
| `.mlkey` | Binary CBOR | Encrypted secret key file |
| `.pem` | ASCII (Base64) | PEM-wrapped `.mlcert` or CSR |

---

## PEM Markers

```
-----BEGIN ML-CERTIFICATE-----
<base64-encoded CBOR Certificate, 64-character line width>
-----END ML-CERTIFICATE-----
```

```
-----BEGIN ML-CERTIFICATE REQUEST-----
<base64-encoded CBOR CertificateSigningRequest, 64-character line width>
-----END ML-CERTIFICATE REQUEST-----
```

---

## Annotated CBOR Examples

### Minimal TBSCertificate (hex dump excerpt)

```
a8                          # map(8)
   01                       # key: version
   01                       # uint(1)
   02                       # key: serial
   50 <16 random bytes>     # bstr(16)
   03                       # key: issuer
   a2                       # map(2)
      01 <cn string>        # key: cn
      02 <org string>       # key: org
   ...
```

### Certificate outer structure

```
a3                          # map(3)
   01                       # key: tbs_bytes
   59 <len> <tbs cbor>      # bstr (variable length)
   02                       # key: sig_alg
   02                       # uint(2) = ML-DSA-65
   03                       # key: signature
   59 <len> <sig bytes>     # bstr (variable length)
```
