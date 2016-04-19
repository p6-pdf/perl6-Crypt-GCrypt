## Enumerations

# == /usr/include/gcrypt.h ==

enum gcry_ctl_cmds is export (
   GCRYCTL_CFB_SYNC => 3,
   GCRYCTL_RESET => 4,
   GCRYCTL_FINALIZE => 5,
   GCRYCTL_GET_KEYLEN => 6,
   GCRYCTL_GET_BLKLEN => 7,
   GCRYCTL_TEST_ALGO => 8,
   GCRYCTL_IS_SECURE => 9,
   GCRYCTL_GET_ASNOID => 10,
   GCRYCTL_ENABLE_ALGO => 11,
   GCRYCTL_DISABLE_ALGO => 12,
   GCRYCTL_DUMP_RANDOM_STATS => 13,
   GCRYCTL_DUMP_SECMEM_STATS => 14,
   GCRYCTL_GET_ALGO_NPKEY => 15,
   GCRYCTL_GET_ALGO_NSKEY => 16,
   GCRYCTL_GET_ALGO_NSIGN => 17,
   GCRYCTL_GET_ALGO_NENCR => 18,
   GCRYCTL_SET_VERBOSITY => 19,
   GCRYCTL_SET_DEBUG_FLAGS => 20,
   GCRYCTL_CLEAR_DEBUG_FLAGS => 21,
   GCRYCTL_USE_SECURE_RNDPOOL => 22,
   GCRYCTL_DUMP_MEMORY_STATS => 23,
   GCRYCTL_INIT_SECMEM => 24,
   GCRYCTL_TERM_SECMEM => 25,
   GCRYCTL_DISABLE_SECMEM_WARN => 27,
   GCRYCTL_SUSPEND_SECMEM_WARN => 28,
   GCRYCTL_RESUME_SECMEM_WARN => 29,
   GCRYCTL_DROP_PRIVS => 30,
   GCRYCTL_ENABLE_M_GUARD => 31,
   GCRYCTL_START_DUMP => 32,
   GCRYCTL_STOP_DUMP => 33,
   GCRYCTL_GET_ALGO_USAGE => 34,
   GCRYCTL_IS_ALGO_ENABLED => 35,
   GCRYCTL_DISABLE_INTERNAL_LOCKING => 36,
   GCRYCTL_DISABLE_SECMEM => 37,
   GCRYCTL_INITIALIZATION_FINISHED => 38,
   GCRYCTL_INITIALIZATION_FINISHED_P => 39,
   GCRYCTL_ANY_INITIALIZATION_P => 40,
   GCRYCTL_SET_CBC_CTS => 41,
   GCRYCTL_SET_CBC_MAC => 42,
   GCRYCTL_ENABLE_QUICK_RANDOM => 44,
   GCRYCTL_SET_RANDOM_SEED_FILE => 45,
   GCRYCTL_UPDATE_RANDOM_SEED_FILE => 46,
   GCRYCTL_SET_THREAD_CBS => 47,
   GCRYCTL_FAST_POLL => 48,
   GCRYCTL_SET_RANDOM_DAEMON_SOCKET => 49,
   GCRYCTL_USE_RANDOM_DAEMON => 50,
   GCRYCTL_FAKED_RANDOM_P => 51,
   GCRYCTL_SET_RNDEGD_SOCKET => 52,
   GCRYCTL_PRINT_CONFIG => 53,
   GCRYCTL_OPERATIONAL_P => 54,
   GCRYCTL_FIPS_MODE_P => 55,
   GCRYCTL_FORCE_FIPS_MODE => 56,
   GCRYCTL_SELFTEST => 57,
   GCRYCTL_DISABLE_HWF => 63,
   GCRYCTL_SET_ENFORCED_FIPS_FLAG => 64,
   GCRYCTL_SET_PREFERRED_RNG_TYPE => 65,
   GCRYCTL_GET_CURRENT_RNG_TYPE => 66,
   GCRYCTL_DISABLE_LOCKED_SECMEM => 67,
   GCRYCTL_DISABLE_PRIV_DROP => 68,
   GCRYCTL_SET_CCM_LENGTHS => 69,
   GCRYCTL_CLOSE_RANDOM_DEVICE => 70,
   GCRYCTL_INACTIVATE_FIPS_FLAG => 71,
   GCRYCTL_REACTIVATE_FIPS_FLAG => 72
);
enum gcry_sexp_format is export (
   GCRYSEXP_FMT_DEFAULT => 0,
   GCRYSEXP_FMT_CANON => 1,
   GCRYSEXP_FMT_BASE64 => 2,
   GCRYSEXP_FMT_ADVANCED => 3
);
enum gcry_mpi_format is export (
   GCRYMPI_FMT_NONE => 0,
   GCRYMPI_FMT_STD => 1,
   GCRYMPI_FMT_PGP => 2,
   GCRYMPI_FMT_SSH => 3,
   GCRYMPI_FMT_HEX => 4,
   GCRYMPI_FMT_USG => 5,
   GCRYMPI_FMT_OPAQUE => 8
);
enum gcry_mpi_flag is export (
   GCRYMPI_FLAG_SECURE => 1,
   GCRYMPI_FLAG_OPAQUE => 2,
   GCRYMPI_FLAG_IMMUTABLE => 4,
   GCRYMPI_FLAG_CONST => 8,
   GCRYMPI_FLAG_USER1 => 256,
   GCRYMPI_FLAG_USER2 => 512,
   GCRYMPI_FLAG_USER3 => 1024,
   GCRYMPI_FLAG_USER4 => 2048
);
enum gcry_cipher_algos is export (
   GCRY_CIPHER_NONE => 0,
   GCRY_CIPHER_IDEA => 1,
   GCRY_CIPHER_3DES => 2,
   GCRY_CIPHER_CAST5 => 3,
   GCRY_CIPHER_BLOWFISH => 4,
   GCRY_CIPHER_SAFER_SK128 => 5,
   GCRY_CIPHER_DES_SK => 6,
   GCRY_CIPHER_AES => 7,
   GCRY_CIPHER_AES192 => 8,
   GCRY_CIPHER_AES256 => 9,
   GCRY_CIPHER_TWOFISH => 10,
   GCRY_CIPHER_ARCFOUR => 301,
   GCRY_CIPHER_DES => 302,
   GCRY_CIPHER_TWOFISH128 => 303,
   GCRY_CIPHER_SERPENT128 => 304,
   GCRY_CIPHER_SERPENT192 => 305,
   GCRY_CIPHER_SERPENT256 => 306,
   GCRY_CIPHER_RFC2268_40 => 307,
   GCRY_CIPHER_RFC2268_128 => 308,
   GCRY_CIPHER_SEED => 309,
   GCRY_CIPHER_CAMELLIA128 => 310,
   GCRY_CIPHER_CAMELLIA192 => 311,
   GCRY_CIPHER_CAMELLIA256 => 312,
   GCRY_CIPHER_SALSA20 => 313,
   GCRY_CIPHER_SALSA20R12 => 314,
   GCRY_CIPHER_GOST28147 => 315
);
enum gcry_cipher_modes is export (
   GCRY_CIPHER_MODE_NONE => 0,
   GCRY_CIPHER_MODE_ECB => 1,
   GCRY_CIPHER_MODE_CFB => 2,
   GCRY_CIPHER_MODE_CBC => 3,
   GCRY_CIPHER_MODE_STREAM => 4,
   GCRY_CIPHER_MODE_OFB => 5,
   GCRY_CIPHER_MODE_CTR => 6,
   GCRY_CIPHER_MODE_AESWRAP => 7,
   GCRY_CIPHER_MODE_CCM => 8,
   GCRY_CIPHER_MODE_GCM => 9
);
enum gcry_cipher_flags is export (
   GCRY_CIPHER_SECURE => 1,
   GCRY_CIPHER_ENABLE_SYNC => 2,
   GCRY_CIPHER_CBC_CTS => 4,
   GCRY_CIPHER_CBC_MAC => 8
);
enum gcry_pk_algos is export (
   GCRY_PK_RSA => 1,
   GCRY_PK_RSA_E => 2,
   GCRY_PK_RSA_S => 3,
   GCRY_PK_ELG_E => 16,
   GCRY_PK_DSA => 17,
   GCRY_PK_ECC => 18,
   GCRY_PK_ELG => 20,
   GCRY_PK_ECDSA => 301,
   GCRY_PK_ECDH => 302
);
enum gcry_md_algos is export (
   GCRY_MD_NONE => 0,
   GCRY_MD_MD5 => 1,
   GCRY_MD_SHA1 => 2,
   GCRY_MD_RMD160 => 3,
   GCRY_MD_MD2 => 5,
   GCRY_MD_TIGER => 6,
   GCRY_MD_HAVAL => 7,
   GCRY_MD_SHA256 => 8,
   GCRY_MD_SHA384 => 9,
   GCRY_MD_SHA512 => 10,
   GCRY_MD_SHA224 => 11,
   GCRY_MD_MD4 => 301,
   GCRY_MD_CRC32 => 302,
   GCRY_MD_CRC32_RFC1510 => 303,
   GCRY_MD_CRC24_RFC2440 => 304,
   GCRY_MD_WHIRLPOOL => 305,
   GCRY_MD_TIGER1 => 306,
   GCRY_MD_TIGER2 => 307,
   GCRY_MD_GOSTR3411_94 => 308,
   GCRY_MD_STRIBOG256 => 309,
   GCRY_MD_STRIBOG512 => 310
);
enum gcry_md_flags is export (
   GCRY_MD_FLAG_SECURE => 1,
   GCRY_MD_FLAG_HMAC => 2,
   GCRY_MD_FLAG_BUGEMU1 => 256
);
enum gcry_mac_algos is export (
   GCRY_MAC_NONE => 0,
   GCRY_MAC_HMAC_SHA256 => 101,
   GCRY_MAC_HMAC_SHA224 => 102,
   GCRY_MAC_HMAC_SHA512 => 103,
   GCRY_MAC_HMAC_SHA384 => 104,
   GCRY_MAC_HMAC_SHA1 => 105,
   GCRY_MAC_HMAC_MD5 => 106,
   GCRY_MAC_HMAC_MD4 => 107,
   GCRY_MAC_HMAC_RMD160 => 108,
   GCRY_MAC_HMAC_TIGER1 => 109,
   GCRY_MAC_HMAC_WHIRLPOOL => 110,
   GCRY_MAC_HMAC_GOSTR3411_94 => 111,
   GCRY_MAC_HMAC_STRIBOG256 => 112,
   GCRY_MAC_HMAC_STRIBOG512 => 113,
   GCRY_MAC_CMAC_AES => 201,
   GCRY_MAC_CMAC_3DES => 202,
   GCRY_MAC_CMAC_CAMELLIA => 203,
   GCRY_MAC_CMAC_CAST5 => 204,
   GCRY_MAC_CMAC_BLOWFISH => 205,
   GCRY_MAC_CMAC_TWOFISH => 206,
   GCRY_MAC_CMAC_SERPENT => 207,
   GCRY_MAC_CMAC_SEED => 208,
   GCRY_MAC_CMAC_RFC2268 => 209,
   GCRY_MAC_CMAC_IDEA => 210,
   GCRY_MAC_CMAC_GOST28147 => 211,
   GCRY_MAC_GMAC_AES => 401,
   GCRY_MAC_GMAC_CAMELLIA => 402,
   GCRY_MAC_GMAC_TWOFISH => 403,
   GCRY_MAC_GMAC_SERPENT => 404,
   GCRY_MAC_GMAC_SEED => 405
);
enum gcry_mac_flags is export (
   GCRY_MAC_FLAG_SECURE => 1
);
enum gcry_kdf_algos is export (
   GCRY_KDF_NONE => 0,
   GCRY_KDF_SIMPLE_S2K => 16,
   GCRY_KDF_SALTED_S2K => 17,
   GCRY_KDF_ITERSALTED_S2K => 19,
   GCRY_KDF_PBKDF1 => 33,
   GCRY_KDF_PBKDF2 => 34,
   GCRY_KDF_SCRYPT => 48
);
enum gcry_rng_types is export (
   GCRY_RNG_TYPE_STANDARD => 1,
   GCRY_RNG_TYPE_FIPS => 2,
   GCRY_RNG_TYPE_SYSTEM => 3
);
enum gcry_random_level is export (
   GCRY_WEAK_RANDOM => 0,
   GCRY_STRONG_RANDOM => 1,
   GCRY_VERY_STRONG_RANDOM => 2
);
enum gcry_log_levels is export (
   GCRY_LOG_CONT => 0,
   GCRY_LOG_INFO => 10,
   GCRY_LOG_WARN => 20,
   GCRY_LOG_ERROR => 30,
   GCRY_LOG_FATAL => 40,
   GCRY_LOG_BUG => 50,
   GCRY_LOG_DEBUG => 100
);

# == /usr/include/x86_64-linux-gnu/gpg-error.h ==

enum gpg_err_source_t is export (
   GPG_ERR_SOURCE_UNKNOWN => 0,
   GPG_ERR_SOURCE_GCRYPT => 1,
   GPG_ERR_SOURCE_GPG => 2,
   GPG_ERR_SOURCE_GPGSM => 3,
   GPG_ERR_SOURCE_GPGAGENT => 4,
   GPG_ERR_SOURCE_PINENTRY => 5,
   GPG_ERR_SOURCE_SCD => 6,
   GPG_ERR_SOURCE_GPGME => 7,
   GPG_ERR_SOURCE_KEYBOX => 8,
   GPG_ERR_SOURCE_KSBA => 9,
   GPG_ERR_SOURCE_DIRMNGR => 10,
   GPG_ERR_SOURCE_GSTI => 11,
   GPG_ERR_SOURCE_GPA => 12,
   GPG_ERR_SOURCE_KLEO => 13,
   GPG_ERR_SOURCE_G13 => 14,
   GPG_ERR_SOURCE_ASSUAN => 15,
   GPG_ERR_SOURCE_TLS => 17,
   GPG_ERR_SOURCE_ANY => 31,
   GPG_ERR_SOURCE_USER_1 => 32,
   GPG_ERR_SOURCE_USER_2 => 33,
   GPG_ERR_SOURCE_USER_3 => 34,
   GPG_ERR_SOURCE_USER_4 => 35,
   GPG_ERR_SOURCE_DIM => 128
);
enum gpg_err_code_t is export (
   GPG_ERR_NO_ERROR => 0,
   GPG_ERR_GENERAL => 1,
   GPG_ERR_UNKNOWN_PACKET => 2,
   GPG_ERR_UNKNOWN_VERSION => 3,
   GPG_ERR_PUBKEY_ALGO => 4,
   GPG_ERR_DIGEST_ALGO => 5,
   GPG_ERR_BAD_PUBKEY => 6,
   GPG_ERR_BAD_SECKEY => 7,
   GPG_ERR_BAD_SIGNATURE => 8,
   GPG_ERR_NO_PUBKEY => 9,
   GPG_ERR_CHECKSUM => 10,
   GPG_ERR_BAD_PASSPHRASE => 11,
   GPG_ERR_CIPHER_ALGO => 12,
   GPG_ERR_KEYRING_OPEN => 13,
   GPG_ERR_INV_PACKET => 14,
   GPG_ERR_INV_ARMOR => 15,
   GPG_ERR_NO_USER_ID => 16,
   GPG_ERR_NO_SECKEY => 17,
   GPG_ERR_WRONG_SECKEY => 18,
   GPG_ERR_BAD_KEY => 19,
   GPG_ERR_COMPR_ALGO => 20,
   GPG_ERR_NO_PRIME => 21,
   GPG_ERR_NO_ENCODING_METHOD => 22,
   GPG_ERR_NO_ENCRYPTION_SCHEME => 23,
   GPG_ERR_NO_SIGNATURE_SCHEME => 24,
   GPG_ERR_INV_ATTR => 25,
   GPG_ERR_NO_VALUE => 26,
   GPG_ERR_NOT_FOUND => 27,
   GPG_ERR_VALUE_NOT_FOUND => 28,
   GPG_ERR_SYNTAX => 29,
   GPG_ERR_BAD_MPI => 30,
   GPG_ERR_INV_PASSPHRASE => 31,
   GPG_ERR_SIG_CLASS => 32,
   GPG_ERR_RESOURCE_LIMIT => 33,
   GPG_ERR_INV_KEYRING => 34,
   GPG_ERR_TRUSTDB => 35,
   GPG_ERR_BAD_CERT => 36,
   GPG_ERR_INV_USER_ID => 37,
   GPG_ERR_UNEXPECTED => 38,
   GPG_ERR_TIME_CONFLICT => 39,
   GPG_ERR_KEYSERVER => 40,
   GPG_ERR_WRONG_PUBKEY_ALGO => 41,
   GPG_ERR_TRIBUTE_TO_D_A => 42,
   GPG_ERR_WEAK_KEY => 43,
   GPG_ERR_INV_KEYLEN => 44,
   GPG_ERR_INV_ARG => 45,
   GPG_ERR_BAD_URI => 46,
   GPG_ERR_INV_URI => 47,
   GPG_ERR_NETWORK => 48,
   GPG_ERR_UNKNOWN_HOST => 49,
   GPG_ERR_SELFTEST_FAILED => 50,
   GPG_ERR_NOT_ENCRYPTED => 51,
   GPG_ERR_NOT_PROCESSED => 52,
   GPG_ERR_UNUSABLE_PUBKEY => 53,
   GPG_ERR_UNUSABLE_SECKEY => 54,
   GPG_ERR_INV_VALUE => 55,
   GPG_ERR_BAD_CERT_CHAIN => 56,
   GPG_ERR_MISSING_CERT => 57,
   GPG_ERR_NO_DATA => 58,
   GPG_ERR_BUG => 59,
   GPG_ERR_NOT_SUPPORTED => 60,
   GPG_ERR_INV_OP => 61,
   GPG_ERR_TIMEOUT => 62,
   GPG_ERR_INTERNAL => 63,
   GPG_ERR_EOF_GCRYPT => 64,
   GPG_ERR_INV_OBJ => 65,
   GPG_ERR_TOO_SHORT => 66,
   GPG_ERR_TOO_LARGE => 67,
   GPG_ERR_NO_OBJ => 68,
   GPG_ERR_NOT_IMPLEMENTED => 69,
   GPG_ERR_CONFLICT => 70,
   GPG_ERR_INV_CIPHER_MODE => 71,
   GPG_ERR_INV_FLAG => 72,
   GPG_ERR_INV_HANDLE => 73,
   GPG_ERR_TRUNCATED => 74,
   GPG_ERR_INCOMPLETE_LINE => 75,
   GPG_ERR_INV_RESPONSE => 76,
   GPG_ERR_NO_AGENT => 77,
   GPG_ERR_AGENT => 78,
   GPG_ERR_INV_DATA => 79,
   GPG_ERR_ASSUAN_SERVER_FAULT => 80,
   GPG_ERR_ASSUAN => 81,
   GPG_ERR_INV_SESSION_KEY => 82,
   GPG_ERR_INV_SEXP => 83,
   GPG_ERR_UNSUPPORTED_ALGORITHM => 84,
   GPG_ERR_NO_PIN_ENTRY => 85,
   GPG_ERR_PIN_ENTRY => 86,
   GPG_ERR_BAD_PIN => 87,
   GPG_ERR_INV_NAME => 88,
   GPG_ERR_BAD_DATA => 89,
   GPG_ERR_INV_PARAMETER => 90,
   GPG_ERR_WRONG_CARD => 91,
   GPG_ERR_NO_DIRMNGR => 92,
   GPG_ERR_DIRMNGR => 93,
   GPG_ERR_CERT_REVOKED => 94,
   GPG_ERR_NO_CRL_KNOWN => 95,
   GPG_ERR_CRL_TOO_OLD => 96,
   GPG_ERR_LINE_TOO_LONG => 97,
   GPG_ERR_NOT_TRUSTED => 98,
   GPG_ERR_CANCELED => 99,
   GPG_ERR_BAD_CA_CERT => 100,
   GPG_ERR_CERT_EXPIRED => 101,
   GPG_ERR_CERT_TOO_YOUNG => 102,
   GPG_ERR_UNSUPPORTED_CERT => 103,
   GPG_ERR_UNKNOWN_SEXP => 104,
   GPG_ERR_UNSUPPORTED_PROTECTION => 105,
   GPG_ERR_CORRUPTED_PROTECTION => 106,
   GPG_ERR_AMBIGUOUS_NAME => 107,
   GPG_ERR_CARD => 108,
   GPG_ERR_CARD_RESET => 109,
   GPG_ERR_CARD_REMOVED => 110,
   GPG_ERR_INV_CARD => 111,
   GPG_ERR_CARD_NOT_PRESENT => 112,
   GPG_ERR_NO_PKCS15_APP => 113,
   GPG_ERR_NOT_CONFIRMED => 114,
   GPG_ERR_CONFIGURATION => 115,
   GPG_ERR_NO_POLICY_MATCH => 116,
   GPG_ERR_INV_INDEX => 117,
   GPG_ERR_INV_ID => 118,
   GPG_ERR_NO_SCDAEMON => 119,
   GPG_ERR_SCDAEMON => 120,
   GPG_ERR_UNSUPPORTED_PROTOCOL => 121,
   GPG_ERR_BAD_PIN_METHOD => 122,
   GPG_ERR_CARD_NOT_INITIALIZED => 123,
   GPG_ERR_UNSUPPORTED_OPERATION => 124,
   GPG_ERR_WRONG_KEY_USAGE => 125,
   GPG_ERR_NOTHING_FOUND => 126,
   GPG_ERR_WRONG_BLOB_TYPE => 127,
   GPG_ERR_MISSING_VALUE => 128,
   GPG_ERR_HARDWARE => 129,
   GPG_ERR_PIN_BLOCKED => 130,
   GPG_ERR_USE_CONDITIONS => 131,
   GPG_ERR_PIN_NOT_SYNCED => 132,
   GPG_ERR_INV_CRL => 133,
   GPG_ERR_BAD_BER => 134,
   GPG_ERR_INV_BER => 135,
   GPG_ERR_ELEMENT_NOT_FOUND => 136,
   GPG_ERR_IDENTIFIER_NOT_FOUND => 137,
   GPG_ERR_INV_TAG => 138,
   GPG_ERR_INV_LENGTH => 139,
   GPG_ERR_INV_KEYINFO => 140,
   GPG_ERR_UNEXPECTED_TAG => 141,
   GPG_ERR_NOT_DER_ENCODED => 142,
   GPG_ERR_NO_CMS_OBJ => 143,
   GPG_ERR_INV_CMS_OBJ => 144,
   GPG_ERR_UNKNOWN_CMS_OBJ => 145,
   GPG_ERR_UNSUPPORTED_CMS_OBJ => 146,
   GPG_ERR_UNSUPPORTED_ENCODING => 147,
   GPG_ERR_UNSUPPORTED_CMS_VERSION => 148,
   GPG_ERR_UNKNOWN_ALGORITHM => 149,
   GPG_ERR_INV_ENGINE => 150,
   GPG_ERR_PUBKEY_NOT_TRUSTED => 151,
   GPG_ERR_DECRYPT_FAILED => 152,
   GPG_ERR_KEY_EXPIRED => 153,
   GPG_ERR_SIG_EXPIRED => 154,
   GPG_ERR_ENCODING_PROBLEM => 155,
   GPG_ERR_INV_STATE => 156,
   GPG_ERR_DUP_VALUE => 157,
   GPG_ERR_MISSING_ACTION => 158,
   GPG_ERR_MODULE_NOT_FOUND => 159,
   GPG_ERR_INV_OID_STRING => 160,
   GPG_ERR_INV_TIME => 161,
   GPG_ERR_INV_CRL_OBJ => 162,
   GPG_ERR_UNSUPPORTED_CRL_VERSION => 163,
   GPG_ERR_INV_CERT_OBJ => 164,
   GPG_ERR_UNKNOWN_NAME => 165,
   GPG_ERR_LOCALE_PROBLEM => 166,
   GPG_ERR_NOT_LOCKED => 167,
   GPG_ERR_PROTOCOL_VIOLATION => 168,
   GPG_ERR_INV_MAC => 169,
   GPG_ERR_INV_REQUEST => 170,
   GPG_ERR_UNKNOWN_EXTN => 171,
   GPG_ERR_UNKNOWN_CRIT_EXTN => 172,
   GPG_ERR_LOCKED => 173,
   GPG_ERR_UNKNOWN_OPTION => 174,
   GPG_ERR_UNKNOWN_COMMAND => 175,
   GPG_ERR_NOT_OPERATIONAL => 176,
   GPG_ERR_NO_PASSPHRASE => 177,
   GPG_ERR_NO_PIN => 178,
   GPG_ERR_NOT_ENABLED => 179,
   GPG_ERR_NO_ENGINE => 180,
   GPG_ERR_MISSING_KEY => 181,
   GPG_ERR_TOO_MANY => 182,
   GPG_ERR_LIMIT_REACHED => 183,
   GPG_ERR_NOT_INITIALIZED => 184,
   GPG_ERR_MISSING_ISSUER_CERT => 185,
   GPG_ERR_NO_KEYSERVER => 186,
   GPG_ERR_INV_CURVE => 187,
   GPG_ERR_UNKNOWN_CURVE => 188,
   GPG_ERR_DUP_KEY => 189,
   GPG_ERR_AMBIGUOUS => 190,
   GPG_ERR_NO_CRYPT_CTX => 191,
   GPG_ERR_WRONG_CRYPT_CTX => 192,
   GPG_ERR_BAD_CRYPT_CTX => 193,
   GPG_ERR_CRYPT_CTX_CONFLICT => 194,
   GPG_ERR_BROKEN_PUBKEY => 195,
   GPG_ERR_BROKEN_SECKEY => 196,
   GPG_ERR_MAC_ALGO => 197,
   GPG_ERR_FULLY_CANCELED => 198,
   GPG_ERR_UNFINISHED => 199,
   GPG_ERR_BUFFER_TOO_SHORT => 200,
   GPG_ERR_SEXP_INV_LEN_SPEC => 201,
   GPG_ERR_SEXP_STRING_TOO_LONG => 202,
   GPG_ERR_SEXP_UNMATCHED_PAREN => 203,
   GPG_ERR_SEXP_NOT_CANONICAL => 204,
   GPG_ERR_SEXP_BAD_CHARACTER => 205,
   GPG_ERR_SEXP_BAD_QUOTATION => 206,
   GPG_ERR_SEXP_ZERO_PREFIX => 207,
   GPG_ERR_SEXP_NESTED_DH => 208,
   GPG_ERR_SEXP_UNMATCHED_DH => 209,
   GPG_ERR_SEXP_UNEXPECTED_PUNC => 210,
   GPG_ERR_SEXP_BAD_HEX_CHAR => 211,
   GPG_ERR_SEXP_ODD_HEX_NUMBERS => 212,
   GPG_ERR_SEXP_BAD_OCT_CHAR => 213,
   GPG_ERR_LEGACY_KEY => 222,
   GPG_ERR_REQUEST_TOO_SHORT => 223,
   GPG_ERR_REQUEST_TOO_LONG => 224,
   GPG_ERR_OBJ_TERM_STATE => 225,
   GPG_ERR_NO_CERT_CHAIN => 226,
   GPG_ERR_CERT_TOO_LARGE => 227,
   GPG_ERR_INV_RECORD => 228,
   GPG_ERR_BAD_MAC => 229,
   GPG_ERR_UNEXPECTED_MSG => 230,
   GPG_ERR_COMPR_FAILED => 231,
   GPG_ERR_WOULD_WRAP => 232,
   GPG_ERR_FATAL_ALERT => 233,
   GPG_ERR_NO_CIPHER => 234,
   GPG_ERR_MISSING_CLIENT_CERT => 235,
   GPG_ERR_CLOSE_NOTIFY => 236,
   GPG_ERR_TICKET_EXPIRED => 237,
   GPG_ERR_BAD_TICKET => 238,
   GPG_ERR_UNKNOWN_IDENTITY => 239,
   GPG_ERR_BAD_HS_CERT => 240,
   GPG_ERR_BAD_HS_CERT_REQ => 241,
   GPG_ERR_BAD_HS_CERT_VER => 242,
   GPG_ERR_BAD_HS_CHANGE_CIPHER => 243,
   GPG_ERR_BAD_HS_CLIENT_HELLO => 244,
   GPG_ERR_BAD_HS_SERVER_HELLO => 245,
   GPG_ERR_BAD_HS_SERVER_HELLO_DONE => 246,
   GPG_ERR_BAD_HS_FINISHED => 247,
   GPG_ERR_BAD_HS_SERVER_KEX => 248,
   GPG_ERR_BAD_HS_CLIENT_KEX => 249,
   GPG_ERR_BOGUS_STRING => 250,
   GPG_ERR_FORBIDDEN => 251,
   GPG_ERR_KEY_DISABLED => 252,
   GPG_ERR_KEY_ON_CARD => 253,
   GPG_ERR_INV_LOCK_OBJ => 254,
   GPG_ERR_ASS_GENERAL => 257,
   GPG_ERR_ASS_ACCEPT_FAILED => 258,
   GPG_ERR_ASS_CONNECT_FAILED => 259,
   GPG_ERR_ASS_INV_RESPONSE => 260,
   GPG_ERR_ASS_INV_VALUE => 261,
   GPG_ERR_ASS_INCOMPLETE_LINE => 262,
   GPG_ERR_ASS_LINE_TOO_LONG => 263,
   GPG_ERR_ASS_NESTED_COMMANDS => 264,
   GPG_ERR_ASS_NO_DATA_CB => 265,
   GPG_ERR_ASS_NO_INQUIRE_CB => 266,
   GPG_ERR_ASS_NOT_A_SERVER => 267,
   GPG_ERR_ASS_NOT_A_CLIENT => 268,
   GPG_ERR_ASS_SERVER_START => 269,
   GPG_ERR_ASS_READ_ERROR => 270,
   GPG_ERR_ASS_WRITE_ERROR => 271,
   GPG_ERR_ASS_TOO_MUCH_DATA => 273,
   GPG_ERR_ASS_UNEXPECTED_CMD => 274,
   GPG_ERR_ASS_UNKNOWN_CMD => 275,
   GPG_ERR_ASS_SYNTAX => 276,
   GPG_ERR_ASS_CANCELED => 277,
   GPG_ERR_ASS_NO_INPUT => 278,
   GPG_ERR_ASS_NO_OUTPUT => 279,
   GPG_ERR_ASS_PARAMETER => 280,
   GPG_ERR_ASS_UNKNOWN_INQUIRE => 281,
   GPG_ERR_LDAP_GENERAL => 721,
   GPG_ERR_LDAP_ATTR_GENERAL => 722,
   GPG_ERR_LDAP_NAME_GENERAL => 723,
   GPG_ERR_LDAP_SECURITY_GENERAL => 724,
   GPG_ERR_LDAP_SERVICE_GENERAL => 725,
   GPG_ERR_LDAP_UPDATE_GENERAL => 726,
   GPG_ERR_LDAP_E_GENERAL => 727,
   GPG_ERR_LDAP_X_GENERAL => 728,
   GPG_ERR_LDAP_OTHER_GENERAL => 729,
   GPG_ERR_LDAP_X_CONNECTING => 750,
   GPG_ERR_LDAP_REFERRAL_LIMIT => 751,
   GPG_ERR_LDAP_CLIENT_LOOP => 752,
   GPG_ERR_LDAP_NO_RESULTS => 754,
   GPG_ERR_LDAP_CONTROL_NOT_FOUND => 755,
   GPG_ERR_LDAP_NOT_SUPPORTED => 756,
   GPG_ERR_LDAP_CONNECT => 757,
   GPG_ERR_LDAP_NO_MEMORY => 758,
   GPG_ERR_LDAP_PARAM => 759,
   GPG_ERR_LDAP_USER_CANCELLED => 760,
   GPG_ERR_LDAP_FILTER => 761,
   GPG_ERR_LDAP_AUTH_UNKNOWN => 762,
   GPG_ERR_LDAP_TIMEOUT => 763,
   GPG_ERR_LDAP_DECODING => 764,
   GPG_ERR_LDAP_ENCODING => 765,
   GPG_ERR_LDAP_LOCAL => 766,
   GPG_ERR_LDAP_SERVER_DOWN => 767,
   GPG_ERR_LDAP_SUCCESS => 768,
   GPG_ERR_LDAP_OPERATIONS => 769,
   GPG_ERR_LDAP_PROTOCOL => 770,
   GPG_ERR_LDAP_TIMELIMIT => 771,
   GPG_ERR_LDAP_SIZELIMIT => 772,
   GPG_ERR_LDAP_COMPARE_FALSE => 773,
   GPG_ERR_LDAP_COMPARE_TRUE => 774,
   GPG_ERR_LDAP_UNSUPPORTED_AUTH => 775,
   GPG_ERR_LDAP_STRONG_AUTH_RQRD => 776,
   GPG_ERR_LDAP_PARTIAL_RESULTS => 777,
   GPG_ERR_LDAP_REFERRAL => 778,
   GPG_ERR_LDAP_ADMINLIMIT => 779,
   GPG_ERR_LDAP_UNAVAIL_CRIT_EXTN => 780,
   GPG_ERR_LDAP_CONFIDENT_RQRD => 781,
   GPG_ERR_LDAP_SASL_BIND_INPROG => 782,
   GPG_ERR_LDAP_NO_SUCH_ATTRIBUTE => 784,
   GPG_ERR_LDAP_UNDEFINED_TYPE => 785,
   GPG_ERR_LDAP_BAD_MATCHING => 786,
   GPG_ERR_LDAP_CONST_VIOLATION => 787,
   GPG_ERR_LDAP_TYPE_VALUE_EXISTS => 788,
   GPG_ERR_LDAP_INV_SYNTAX => 789,
   GPG_ERR_LDAP_NO_SUCH_OBJ => 800,
   GPG_ERR_LDAP_ALIAS_PROBLEM => 801,
   GPG_ERR_LDAP_INV_DN_SYNTAX => 802,
   GPG_ERR_LDAP_IS_LEAF => 803,
   GPG_ERR_LDAP_ALIAS_DEREF => 804,
   GPG_ERR_LDAP_X_PROXY_AUTH_FAIL => 815,
   GPG_ERR_LDAP_BAD_AUTH => 816,
   GPG_ERR_LDAP_INV_CREDENTIALS => 817,
   GPG_ERR_LDAP_INSUFFICIENT_ACC => 818,
   GPG_ERR_LDAP_BUSY => 819,
   GPG_ERR_LDAP_UNAVAILABLE => 820,
   GPG_ERR_LDAP_UNWILL_TO_PERFORM => 821,
   GPG_ERR_LDAP_LOOP_DETECT => 822,
   GPG_ERR_LDAP_NAMING_VIOLATION => 832,
   GPG_ERR_LDAP_OBJ_CLS_VIOLATION => 833,
   GPG_ERR_LDAP_NOT_ALLOW_NONLEAF => 834,
   GPG_ERR_LDAP_NOT_ALLOW_ON_RDN => 835,
   GPG_ERR_LDAP_ALREADY_EXISTS => 836,
   GPG_ERR_LDAP_NO_OBJ_CLASS_MODS => 837,
   GPG_ERR_LDAP_RESULTS_TOO_LARGE => 838,
   GPG_ERR_LDAP_AFFECTS_MULT_DSAS => 839,
   GPG_ERR_LDAP_VLV => 844,
   GPG_ERR_LDAP_OTHER => 848,
   GPG_ERR_LDAP_CUP_RESOURCE_LIMIT => 881,
   GPG_ERR_LDAP_CUP_SEC_VIOLATION => 882,
   GPG_ERR_LDAP_CUP_INV_DATA => 883,
   GPG_ERR_LDAP_CUP_UNSUP_SCHEME => 884,
   GPG_ERR_LDAP_CUP_RELOAD => 885,
   GPG_ERR_LDAP_CANCELLED => 886,
   GPG_ERR_LDAP_NO_SUCH_OPERATION => 887,
   GPG_ERR_LDAP_TOO_LATE => 888,
   GPG_ERR_LDAP_CANNOT_CANCEL => 889,
   GPG_ERR_LDAP_ASSERTION_FAILED => 890,
   GPG_ERR_LDAP_PROX_AUTH_DENIED => 891,
   GPG_ERR_USER_1 => 1024,
   GPG_ERR_USER_2 => 1025,
   GPG_ERR_USER_3 => 1026,
   GPG_ERR_USER_4 => 1027,
   GPG_ERR_USER_5 => 1028,
   GPG_ERR_USER_6 => 1029,
   GPG_ERR_USER_7 => 1030,
   GPG_ERR_USER_8 => 1031,
   GPG_ERR_USER_9 => 1032,
   GPG_ERR_USER_10 => 1033,
   GPG_ERR_USER_11 => 1034,
   GPG_ERR_USER_12 => 1035,
   GPG_ERR_USER_13 => 1036,
   GPG_ERR_USER_14 => 1037,
   GPG_ERR_USER_15 => 1038,
   GPG_ERR_USER_16 => 1039,
   GPG_ERR_MISSING_ERRNO => 16381,
   GPG_ERR_UNKNOWN_ERRNO => 16382,
   GPG_ERR_EOF => 16383,
   GPG_ERR_E2BIG => 32768,
   GPG_ERR_EACCES => 32769,
   GPG_ERR_EADDRINUSE => 32770,
   GPG_ERR_EADDRNOTAVAIL => 32771,
   GPG_ERR_EADV => 32772,
   GPG_ERR_EAFNOSUPPORT => 32773,
   GPG_ERR_EAGAIN => 32774,
   GPG_ERR_EALREADY => 32775,
   GPG_ERR_EAUTH => 32776,
   GPG_ERR_EBACKGROUND => 32777,
   GPG_ERR_EBADE => 32778,
   GPG_ERR_EBADF => 32779,
   GPG_ERR_EBADFD => 32780,
   GPG_ERR_EBADMSG => 32781,
   GPG_ERR_EBADR => 32782,
   GPG_ERR_EBADRPC => 32783,
   GPG_ERR_EBADRQC => 32784,
   GPG_ERR_EBADSLT => 32785,
   GPG_ERR_EBFONT => 32786,
   GPG_ERR_EBUSY => 32787,
   GPG_ERR_ECANCELED => 32788,
   GPG_ERR_ECHILD => 32789,
   GPG_ERR_ECHRNG => 32790,
   GPG_ERR_ECOMM => 32791,
   GPG_ERR_ECONNABORTED => 32792,
   GPG_ERR_ECONNREFUSED => 32793,
   GPG_ERR_ECONNRESET => 32794,
   GPG_ERR_ED => 32795,
   GPG_ERR_EDEADLK => 32796,
   GPG_ERR_EDEADLOCK => 32797,
   GPG_ERR_EDESTADDRREQ => 32798,
   GPG_ERR_EDIED => 32799,
   GPG_ERR_EDOM => 32800,
   GPG_ERR_EDOTDOT => 32801,
   GPG_ERR_EDQUOT => 32802,
   GPG_ERR_EEXIST => 32803,
   GPG_ERR_EFAULT => 32804,
   GPG_ERR_EFBIG => 32805,
   GPG_ERR_EFTYPE => 32806,
   GPG_ERR_EGRATUITOUS => 32807,
   GPG_ERR_EGREGIOUS => 32808,
   GPG_ERR_EHOSTDOWN => 32809,
   GPG_ERR_EHOSTUNREACH => 32810,
   GPG_ERR_EIDRM => 32811,
   GPG_ERR_EIEIO => 32812,
   GPG_ERR_EILSEQ => 32813,
   GPG_ERR_EINPROGRESS => 32814,
   GPG_ERR_EINTR => 32815,
   GPG_ERR_EINVAL => 32816,
   GPG_ERR_EIO => 32817,
   GPG_ERR_EISCONN => 32818,
   GPG_ERR_EISDIR => 32819,
   GPG_ERR_EISNAM => 32820,
   GPG_ERR_EL2HLT => 32821,
   GPG_ERR_EL2NSYNC => 32822,
   GPG_ERR_EL3HLT => 32823,
   GPG_ERR_EL3RST => 32824,
   GPG_ERR_ELIBACC => 32825,
   GPG_ERR_ELIBBAD => 32826,
   GPG_ERR_ELIBEXEC => 32827,
   GPG_ERR_ELIBMAX => 32828,
   GPG_ERR_ELIBSCN => 32829,
   GPG_ERR_ELNRNG => 32830,
   GPG_ERR_ELOOP => 32831,
   GPG_ERR_EMEDIUMTYPE => 32832,
   GPG_ERR_EMFILE => 32833,
   GPG_ERR_EMLINK => 32834,
   GPG_ERR_EMSGSIZE => 32835,
   GPG_ERR_EMULTIHOP => 32836,
   GPG_ERR_ENAMETOOLONG => 32837,
   GPG_ERR_ENAVAIL => 32838,
   GPG_ERR_ENEEDAUTH => 32839,
   GPG_ERR_ENETDOWN => 32840,
   GPG_ERR_ENETRESET => 32841,
   GPG_ERR_ENETUNREACH => 32842,
   GPG_ERR_ENFILE => 32843,
   GPG_ERR_ENOANO => 32844,
   GPG_ERR_ENOBUFS => 32845,
   GPG_ERR_ENOCSI => 32846,
   GPG_ERR_ENODATA => 32847,
   GPG_ERR_ENODEV => 32848,
   GPG_ERR_ENOENT => 32849,
   GPG_ERR_ENOEXEC => 32850,
   GPG_ERR_ENOLCK => 32851,
   GPG_ERR_ENOLINK => 32852,
   GPG_ERR_ENOMEDIUM => 32853,
   GPG_ERR_ENOMEM => 32854,
   GPG_ERR_ENOMSG => 32855,
   GPG_ERR_ENONET => 32856,
   GPG_ERR_ENOPKG => 32857,
   GPG_ERR_ENOPROTOOPT => 32858,
   GPG_ERR_ENOSPC => 32859,
   GPG_ERR_ENOSR => 32860,
   GPG_ERR_ENOSTR => 32861,
   GPG_ERR_ENOSYS => 32862,
   GPG_ERR_ENOTBLK => 32863,
   GPG_ERR_ENOTCONN => 32864,
   GPG_ERR_ENOTDIR => 32865,
   GPG_ERR_ENOTEMPTY => 32866,
   GPG_ERR_ENOTNAM => 32867,
   GPG_ERR_ENOTSOCK => 32868,
   GPG_ERR_ENOTSUP => 32869,
   GPG_ERR_ENOTTY => 32870,
   GPG_ERR_ENOTUNIQ => 32871,
   GPG_ERR_ENXIO => 32872,
   GPG_ERR_EOPNOTSUPP => 32873,
   GPG_ERR_EOVERFLOW => 32874,
   GPG_ERR_EPERM => 32875,
   GPG_ERR_EPFNOSUPPORT => 32876,
   GPG_ERR_EPIPE => 32877,
   GPG_ERR_EPROCLIM => 32878,
   GPG_ERR_EPROCUNAVAIL => 32879,
   GPG_ERR_EPROGMISMATCH => 32880,
   GPG_ERR_EPROGUNAVAIL => 32881,
   GPG_ERR_EPROTO => 32882,
   GPG_ERR_EPROTONOSUPPORT => 32883,
   GPG_ERR_EPROTOTYPE => 32884,
   GPG_ERR_ERANGE => 32885,
   GPG_ERR_EREMCHG => 32886,
   GPG_ERR_EREMOTE => 32887,
   GPG_ERR_EREMOTEIO => 32888,
   GPG_ERR_ERESTART => 32889,
   GPG_ERR_EROFS => 32890,
   GPG_ERR_ERPCMISMATCH => 32891,
   GPG_ERR_ESHUTDOWN => 32892,
   GPG_ERR_ESOCKTNOSUPPORT => 32893,
   GPG_ERR_ESPIPE => 32894,
   GPG_ERR_ESRCH => 32895,
   GPG_ERR_ESRMNT => 32896,
   GPG_ERR_ESTALE => 32897,
   GPG_ERR_ESTRPIPE => 32898,
   GPG_ERR_ETIME => 32899,
   GPG_ERR_ETIMEDOUT => 32900,
   GPG_ERR_ETOOMANYREFS => 32901,
   GPG_ERR_ETXTBSY => 32902,
   GPG_ERR_EUCLEAN => 32903,
   GPG_ERR_EUNATCH => 32904,
   GPG_ERR_EUSERS => 32905,
   GPG_ERR_EWOULDBLOCK => 32906,
   GPG_ERR_EXDEV => 32907,
   GPG_ERR_EXFULL => 32908,
   GPG_ERR_CODE_DIM => 65536
);
enum gpgrt_syshd_types is export (
   GPGRT_SYSHD_NONE => 0,
   GPGRT_SYSHD_FD => 1,
   GPGRT_SYSHD_SOCK => 2,
   GPGRT_SYSHD_RVID => 3,
   GPGRT_SYSHD_HANDLE => 4
);
## Structures


# == /usr/include/gcrypt.h ==

class gcry_thread_cbs is repr('CStruct') is export {
	has uint32                        $.option; # unsigned int option
}
class gcry_context is repr('CStruct') is export {
}
class gcry_mpi is repr('CStruct') is export {
}
class gcry_mpi_point is repr('CStruct') is export {
}
class gcry_buffer_t is repr('CStruct') is export {
	has size_t                        $.size; # Typedef<size_t>->|long unsigned int| size
	has size_t                        $.off; # Typedef<size_t>->|long unsigned int| off
	has size_t                        $.len; # Typedef<size_t>->|long unsigned int| len
	has Pointer                       $.data; # void* data
}
class gcry_sexp is repr('CStruct') is export {
}
class gcry_cipher_handle is repr('CStruct') is export {
}
class gcry_md_context is repr('CStruct') is export {
}
class gcry_md_handle is repr('CStruct') is export {
	has gcry_md_context               $.ctx; # gcry_md_context* ctx
	has int32                         $.bufpos; # int bufpos
	has int32                         $.bufsize; # int bufsize
	has CArray[uint8]                 $.buf; # unsigned char[1] buf
}
class gcry_mac_handle is repr('CStruct') is export {
}

# == <built-in> ==

class __va_list_tag is repr('CStruct') is export {
}

# == /usr/include/x86_64-linux-gnu/gpg-error.h ==

class gpgrt_lock_t is repr('CStruct') is export {
	has long                          $._vers; # long int _vers
	HAS gpgrt_lock_t_u_Union          $.u; # Union u
}
class _gpgrt_stream_internal is repr('CStruct') is export {
}
class _gpgrt__stream is repr('CStruct') is export {
	HAS N14_gpgrt__stream4._28E       $.flags; # N14_gpgrt__stream4._28E flags
	has Pointer[uint8]                $.buffer; # unsigned char* buffer
	has size_t                        $.buffer_size; # Typedef<size_t>->|long unsigned int| buffer_size
	has size_t                        $.data_len; # Typedef<size_t>->|long unsigned int| data_len
	has size_t                        $.data_offset; # Typedef<size_t>->|long unsigned int| data_offset
	has size_t                        $.data_flushed; # Typedef<size_t>->|long unsigned int| data_flushed
	has Pointer[uint8]                $.unread_buffer; # unsigned char* unread_buffer
	has size_t                        $.unread_buffer_size; # Typedef<size_t>->|long unsigned int| unread_buffer_size
	has size_t                        $.unread_data_len; # Typedef<size_t>->|long unsigned int| unread_data_len
	has _gpgrt_stream_internal        $.intern; # _gpgrt_stream_internal* intern
}
class N14_gpgrt__stream4._28E is repr('CStruct') is export {
	has uint32                        $.magic; # unsigned int magic
	has uint32                        $.writing; # unsigned int writing
	has uint32                        $.reserved; # unsigned int reserved
}
class _gpgrt_cookie_io_functions is repr('CStruct') is export {
	has Pointer                       $.func_read; # Typedef<gpgrt_cookie_read_function_t>->|F:Typedef<ssize_t>->|Typedef<__ssize_t>->|long int|| ( void*, void*, Typedef<size_t>->|long unsigned int|)*| func_read
	has Pointer                       $.func_write; # Typedef<gpgrt_cookie_write_function_t>->|F:Typedef<ssize_t>->|Typedef<__ssize_t>->|long int|| ( void*, const void*, Typedef<size_t>->|long unsigned int|)*| func_write
	has Pointer                       $.func_seek; # Typedef<gpgrt_cookie_seek_function_t>->|F:int ( void*, Typedef<gpgrt_off_t>->|long int|*, int)*| func_seek
	has Pointer                       $.func_close; # Typedef<gpgrt_cookie_close_function_t>->|F:int ( void*)*| func_close
}
class _gpgrt_syshd_u_Union is repr('CUnion') is export {
	has int32                         $.fd; # int fd
	has int32                         $.sock; # int sock
	has int32                         $.rvid; # int rvid
	has Pointer                       $.handle; # void* handle
}
class _gpgrt_syshd is repr('CStruct') is export {
	has int32                         $.type; # gpgrt_syshd_types type
	HAS _gpgrt_syshd_u_Union          $.u; # Union u
}

# == /usr/include/wchar.h ==

class __mbstate_t is repr('CStruct') is export {
	has int32                         $.__count; # int __count
	HAS __mbstate_t___value_Union     $.__value; # Union __value
}

# == /usr/include/time.h ==

class timespec is repr('CStruct') is export {
	has __time_t                      $.tv_sec; # Typedef<__time_t>->|long int| tv_sec
	has __syscall_slong_t             $.tv_nsec; # Typedef<__syscall_slong_t>->|long int| tv_nsec
}

# == /usr/include/_G_config.h ==

class _G_fpos_t is repr('CStruct') is export {
	has __off_t                       $.__pos; # Typedef<__off_t>->|long int| __pos
	HAS __mbstate_t                   $.__state; # __mbstate_t __state
}
class _G_fpos64_t is repr('CStruct') is export {
	has __off64_t                     $.__pos; # Typedef<__off64_t>->|long int| __pos
	HAS __mbstate_t                   $.__state; # __mbstate_t __state
}

# == /usr/include/xlocale.h ==

class __locale_struct is repr('CStruct') is export {
	has CArray[__locale_data]         $.__locales; # __locale_data*[13] __locales
	has Pointer[uint16]               $.__ctype_b; # const short unsigned int* __ctype_b
	has Pointer[int32]                $.__ctype_tolower; # const int* __ctype_tolower
	has Pointer[int32]                $.__ctype_toupper; # const int* __ctype_toupper
	has CArray[Str]                   $.__names; # const char*[13] __names
}
class __locale_data is repr('CStruct') is export {
}
## Extras stuff

constant cookie_io_functions_t is export := _IO_cookie_io_functions_t;
constant __pthread_list_t is export := __pthread_internal_list;
constant fpos_t is export := _G_fpos_t;
constant gpgrt_cookie_io_functions_t is export := _gpgrt_cookie_io_functions;
constant __FILE is export := _IO_FILE;
constant sigset_t is export := __sigset_t;
constant fpos64_t is export := _G_fpos64_t;
constant fsid_t is export := __fsid_t;
constant gpgrt_syshd_t is export := _gpgrt_syshd;
constant _IO_lock_tPtr is export = Pointer;
constant FILE is export := _IO_FILE;
## Functions


# == /usr/include/gcrypt.h ==

#-From /usr/include/gcrypt.h:140
#static GPG_ERR_INLINE gcry_error_t
#gcry_err_make (gcry_err_source_t source, gcry_err_code_t code)
sub gcry_err_make(int32                         $source # Typedef<gcry_err_source_t>->|gpg_err_source_t|
                 ,int32                         $code # Typedef<gcry_err_code_t>->|gpg_err_code_t|
                  ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:152
#static GPG_ERR_INLINE gcry_error_t
#gcry_error (gcry_err_code_t code)
sub gcry_error(int32 $code # Typedef<gcry_err_code_t>->|gpg_err_code_t|
               ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:158
#static GPG_ERR_INLINE gcry_err_code_t
#gcry_err_code (gcry_error_t err)
sub gcry_err_code(gpg_error_t $err # Typedef<gcry_error_t>->|Typedef<gpg_error_t>->|unsigned int||
                  ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:165
#static GPG_ERR_INLINE gcry_err_source_t
#gcry_err_source (gcry_error_t err)
sub gcry_err_source(gpg_error_t $err # Typedef<gcry_error_t>->|Typedef<gpg_error_t>->|unsigned int||
                    ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:172
#/* Return a pointer to a string containing a description of the error
#   code in the error value ERR.  */
#const char *gcry_strerror (gcry_error_t err);
sub gcry_strerror(gpg_error_t $err # Typedef<gcry_error_t>->|Typedef<gpg_error_t>->|unsigned int||
                  ) is native(LIB) returns Str is export { * }

#-From /usr/include/gcrypt.h:176
#/* Return a pointer to a string containing a description of the error
#   source in the error value ERR.  */
#const char *gcry_strsource (gcry_error_t err);
sub gcry_strsource(gpg_error_t $err # Typedef<gcry_error_t>->|Typedef<gpg_error_t>->|unsigned int||
                   ) is native(LIB) returns Str is export { * }

#-From /usr/include/gcrypt.h:181
#/* Retrieve the error code for the system error ERR.  This returns
#   GPG_ERR_UNKNOWN_ERRNO if the system error is not mapped (report
#   this).  */
#gcry_err_code_t gcry_err_code_from_errno (int err);
sub gcry_err_code_from_errno(int32 $err # int
                             ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:185
#/* Retrieve the system error for the error code CODE.  This returns 0
#   if CODE is not a system error code.  */
#int gcry_err_code_to_errno (gcry_err_code_t code);
sub gcry_err_code_to_errno(int32 $code # Typedef<gcry_err_code_t>->|gpg_err_code_t|
                           ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:189
#/* Return an error value with the error source SOURCE and the system
#   error ERR.  */
#gcry_error_t gcry_err_make_from_errno (gcry_err_source_t source, int err);
sub gcry_err_make_from_errno(int32                         $source # Typedef<gcry_err_source_t>->|gpg_err_source_t|
                            ,int32                         $err # int
                             ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:192
#/* Return an error value with the system error ERR.  */
#gcry_err_code_t gcry_error_from_errno (int err);
sub gcry_error_from_errno(int32 $err # int
                          ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:258
#/* Check that the library fulfills the version requirement.  */
#const char *gcry_check_version (const char *req_version);
sub gcry_check_version(Str $req_version # const char*
                       ) is native(LIB) returns Str is export { * }

#-From /usr/include/gcrypt.h:334
#/* Perform various operations defined by CMD. */
#gcry_error_t gcry_control (enum gcry_ctl_cmds CMD, ...);
sub gcry_control(int32 $CMD # gcry_ctl_cmds
                 ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:363
#/* Create an new S-expression object from BUFFER of size LENGTH and
#   return it in RETSEXP.  With AUTODETECT set to 0 the data in BUFFER
#   is expected to be in canonized format.  */
#gcry_error_t gcry_sexp_new (gcry_sexp_t *retsexp,
#                            const void *buffer, size_t length,
#                            int autodetect);
sub gcry_sexp_new(Pointer[gcry_sexp]            $retsexp # Typedef<gcry_sexp_t>->|gcry_sexp*|*
                 ,Pointer                       $buffer # const void*
                 ,size_t                        $length # Typedef<size_t>->|long unsigned int|
                 ,int32                         $autodetect # int
                  ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:369
# /* Same as gcry_sexp_new but allows to pass a FREEFNC which has the
#    effect to transfer ownership of BUFFER to the created object.  */
#gcry_error_t gcry_sexp_create (gcry_sexp_t *retsexp,
#                               void *buffer, size_t length,
#                               int autodetect, void (*freefnc) (void *));
sub gcry_sexp_create(Pointer[gcry_sexp]            $retsexp # Typedef<gcry_sexp_t>->|gcry_sexp*|*
                    ,Pointer                       $buffer # void*
                    ,size_t                        $length # Typedef<size_t>->|long unsigned int|
                    ,int32                         $autodetect # int
                    ,&freefnc (Pointer) # F:void ( void*)*
                     ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:374
#/* Scan BUFFER and return a new S-expression object in RETSEXP.  This
#   function expects a printf like string in BUFFER.  */
#gcry_error_t gcry_sexp_sscan (gcry_sexp_t *retsexp, size_t *erroff,
#                              const char *buffer, size_t length);
sub gcry_sexp_sscan(Pointer[gcry_sexp]            $retsexp # Typedef<gcry_sexp_t>->|gcry_sexp*|*
                   ,Pointer[size_t]               $erroff # Typedef<size_t>->|long unsigned int|*
                   ,Str                           $buffer # const char*
                   ,size_t                        $length # Typedef<size_t>->|long unsigned int|
                    ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:379
#/* Same as gcry_sexp_sscan but expects a string in FORMAT and can thus
#   only be used for certain encodings.  */
#gcry_error_t gcry_sexp_build (gcry_sexp_t *retsexp, size_t *erroff,
#                              const char *format, ...);
sub gcry_sexp_build(Pointer[gcry_sexp]            $retsexp # Typedef<gcry_sexp_t>->|gcry_sexp*|*
                   ,Pointer[size_t]               $erroff # Typedef<size_t>->|long unsigned int|*
                   ,Str                           $format # const char*
                    ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:384
#/* Like gcry_sexp_build, but uses an array instead of variable
#   function arguments.  */
#gcry_error_t gcry_sexp_build_array (gcry_sexp_t *retsexp, size_t *erroff,
#				    const char *format, void **arg_list);
sub gcry_sexp_build_array(Pointer[gcry_sexp]            $retsexp # Typedef<gcry_sexp_t>->|gcry_sexp*|*
                         ,Pointer[size_t]               $erroff # Typedef<size_t>->|long unsigned int|*
                         ,Str                           $format # const char*
                         ,Pointer[Pointer]              $arg_list # void**
                          ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:387
#/* Release the S-expression object SEXP */
#void gcry_sexp_release (gcry_sexp_t sexp);
sub gcry_sexp_release(gcry_sexp $sexp # Typedef<gcry_sexp_t>->|gcry_sexp*|
                      ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:392
#/* Calculate the length of an canonized S-expresion in BUFFER and
#   check for a valid encoding. */
#size_t gcry_sexp_canon_len (const unsigned char *buffer, size_t length,
#                            size_t *erroff, gcry_error_t *errcode);
sub gcry_sexp_canon_len(Pointer[uint8]                $buffer # const unsigned char*
                       ,size_t                        $length # Typedef<size_t>->|long unsigned int|
                       ,Pointer[size_t]               $erroff # Typedef<size_t>->|long unsigned int|*
                       ,Pointer[gpg_error_t]          $errcode # Typedef<gcry_error_t>->|Typedef<gpg_error_t>->|unsigned int||*
                        ) is native(LIB) returns size_t is export { * }

#-From /usr/include/gcrypt.h:397
#/* Copies the S-expression object SEXP into BUFFER using the format
#   specified in MODE.  */
#size_t gcry_sexp_sprint (gcry_sexp_t sexp, int mode, void *buffer,
#                         size_t maxlength);
sub gcry_sexp_sprint(gcry_sexp                     $sexp # Typedef<gcry_sexp_t>->|gcry_sexp*|
                    ,int32                         $mode # int
                    ,Pointer                       $buffer # void*
                    ,size_t                        $maxlength # Typedef<size_t>->|long unsigned int|
                     ) is native(LIB) returns size_t is export { * }

#-From /usr/include/gcrypt.h:401
#/* Dumps the S-expression object A in a format suitable for debugging
#   to Libgcrypt's logging stream.  */
#void gcry_sexp_dump (const gcry_sexp_t a);
sub gcry_sexp_dump(gcry_sexp $a # const Typedef<gcry_sexp_t>->|gcry_sexp*|
                   ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:403
#gcry_sexp_t gcry_sexp_cons (const gcry_sexp_t a, const gcry_sexp_t b);
sub gcry_sexp_cons(gcry_sexp                     $a # const Typedef<gcry_sexp_t>->|gcry_sexp*|
                  ,gcry_sexp                     $b # const Typedef<gcry_sexp_t>->|gcry_sexp*|
                   ) is native(LIB) returns gcry_sexp is export { * }

#-From /usr/include/gcrypt.h:404
#gcry_sexp_t gcry_sexp_alist (const gcry_sexp_t *array);
sub gcry_sexp_alist(Pointer[gcry_sexp] $array # const Typedef<gcry_sexp_t>->|gcry_sexp*|*
                    ) is native(LIB) returns gcry_sexp is export { * }

#-From /usr/include/gcrypt.h:405
#gcry_sexp_t gcry_sexp_vlist (const gcry_sexp_t a, ...);
sub gcry_sexp_vlist(gcry_sexp $a # const Typedef<gcry_sexp_t>->|gcry_sexp*|
                    ) is native(LIB) returns gcry_sexp is export { * }

#-From /usr/include/gcrypt.h:406
#gcry_sexp_t gcry_sexp_append (const gcry_sexp_t a, const gcry_sexp_t n);
sub gcry_sexp_append(gcry_sexp                     $a # const Typedef<gcry_sexp_t>->|gcry_sexp*|
                    ,gcry_sexp                     $n # const Typedef<gcry_sexp_t>->|gcry_sexp*|
                     ) is native(LIB) returns gcry_sexp is export { * }

#-From /usr/include/gcrypt.h:407
#gcry_sexp_t gcry_sexp_prepend (const gcry_sexp_t a, const gcry_sexp_t n);
sub gcry_sexp_prepend(gcry_sexp                     $a # const Typedef<gcry_sexp_t>->|gcry_sexp*|
                     ,gcry_sexp                     $n # const Typedef<gcry_sexp_t>->|gcry_sexp*|
                      ) is native(LIB) returns gcry_sexp is export { * }

#-From /usr/include/gcrypt.h:415
#/* Scan the S-expression for a sublist with a type (the car of the
#   list) matching the string TOKEN.  If TOKLEN is not 0, the token is
#   assumed to be raw memory of this length.  The function returns a
#   newly allocated S-expression consisting of the found sublist or
#   `NULL' when not found.  */
#gcry_sexp_t gcry_sexp_find_token (gcry_sexp_t list,
#                                const char *tok, size_t toklen);
sub gcry_sexp_find_token(gcry_sexp                     $list # Typedef<gcry_sexp_t>->|gcry_sexp*|
                        ,Str                           $tok # const char*
                        ,size_t                        $toklen # Typedef<size_t>->|long unsigned int|
                         ) is native(LIB) returns gcry_sexp is export { * }

#-From /usr/include/gcrypt.h:418
#/* Return the length of the LIST.  For a valid S-expression this
#   should be at least 1.  */
#int gcry_sexp_length (const gcry_sexp_t list);
sub gcry_sexp_length(gcry_sexp $list # const Typedef<gcry_sexp_t>->|gcry_sexp*|
                     ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:423
#/* Create and return a new S-expression from the element with index
#   NUMBER in LIST.  Note that the first element has the index 0.  If
#   there is no such element, `NULL' is returned.  */
#gcry_sexp_t gcry_sexp_nth (const gcry_sexp_t list, int number);
sub gcry_sexp_nth(gcry_sexp                     $list # const Typedef<gcry_sexp_t>->|gcry_sexp*|
                 ,int32                         $number # int
                  ) is native(LIB) returns gcry_sexp is export { * }

#-From /usr/include/gcrypt.h:428
#   string. `NULL' is returned in case of a problem.  */
#gcry_sexp_t gcry_sexp_car (const gcry_sexp_t list);
sub gcry_sexp_car(gcry_sexp $list # const Typedef<gcry_sexp_t>->|gcry_sexp*|
                  ) is native(LIB) returns gcry_sexp is export { * }

#-From /usr/include/gcrypt.h:435
#/* Create and return a new list form all elements except for the first
#   one.  Note, that this function may return an invalid S-expression
#   because it is not guaranteed, that the type exists and is a string.
#   However, for parsing a complex S-expression it might be useful for
#   intermediate lists.  Returns `NULL' on error.  */
#gcry_sexp_t gcry_sexp_cdr (const gcry_sexp_t list);
sub gcry_sexp_cdr(gcry_sexp $list # const Typedef<gcry_sexp_t>->|gcry_sexp*|
                  ) is native(LIB) returns gcry_sexp is export { * }

#-From /usr/include/gcrypt.h:437
#gcry_sexp_t gcry_sexp_cadr (const gcry_sexp_t list);
sub gcry_sexp_cadr(gcry_sexp $list # const Typedef<gcry_sexp_t>->|gcry_sexp*|
                   ) is native(LIB) returns gcry_sexp is export { * }

#-From /usr/include/gcrypt.h:447
#/* This function is used to get data from a LIST.  A pointer to the
#   actual data with index NUMBER is returned and the length of this
#   data will be stored to DATALEN.  If there is no data at the given
#   index or the index represents another list, `NULL' is returned.
#   *Note:* The returned pointer is valid as long as LIST is not
#   modified or released.  */
#const char *gcry_sexp_nth_data (const gcry_sexp_t list, int number,
#                                size_t *datalen);
sub gcry_sexp_nth_data(gcry_sexp                     $list # const Typedef<gcry_sexp_t>->|gcry_sexp*|
                      ,int32                         $number # int
                      ,Pointer[size_t]               $datalen # Typedef<size_t>->|long unsigned int|*
                       ) is native(LIB) returns Str is export { * }

#-From /usr/include/gcrypt.h:454
#/* This function is used to get data from a LIST.  A malloced buffer to the
#   data with index NUMBER is returned and the length of this
#   data will be stored to RLENGTH.  If there is no data at the given
#   index or the index represents another list, `NULL' is returned.  */
#void *gcry_sexp_nth_buffer (const gcry_sexp_t list, int number,
#                            size_t *rlength);
sub gcry_sexp_nth_buffer(gcry_sexp                     $list # const Typedef<gcry_sexp_t>->|gcry_sexp*|
                        ,int32                         $number # int
                        ,Pointer[size_t]               $rlength # Typedef<size_t>->|long unsigned int|*
                         ) is native(LIB) returns Pointer is export { * }

#-From /usr/include/gcrypt.h:461
#/* This function is used to get and convert data from a LIST.  The
#   data is assumed to be a Nul terminated string.  The caller must
#   release the returned value using `gcry_free'.  If there is no data
#   at the given index, the index represents a list or the value can't
#   be converted to a string, `NULL' is returned.  */
#char *gcry_sexp_nth_string (gcry_sexp_t list, int number);
sub gcry_sexp_nth_string(gcry_sexp                     $list # Typedef<gcry_sexp_t>->|gcry_sexp*|
                        ,int32                         $number # int
                         ) is native(LIB) returns Str is export { * }

#-From /usr/include/gcrypt.h:469
#/* This function is used to get and convert data from a LIST. This
#   data is assumed to be an MPI stored in the format described by
#   MPIFMT and returned as a standard Libgcrypt MPI.  The caller must
#   release this returned value using `gcry_mpi_release'.  If there is
#   no data at the given index, the index represents a list or the
#   value can't be converted to an MPI, `NULL' is returned.  */
#gcry_mpi_t gcry_sexp_nth_mpi (gcry_sexp_t list, int number, int mpifmt);
sub gcry_sexp_nth_mpi(gcry_sexp                     $list # Typedef<gcry_sexp_t>->|gcry_sexp*|
                     ,int32                         $number # int
                     ,int32                         $mpifmt # int
                      ) is native(LIB) returns gcry_mpi is export { * }

#-From /usr/include/gcrypt.h:476
#/* Convenience fucntion to extract parameters from an S-expression
# * using a list of single letter parameters.  */
#gpg_error_t gcry_sexp_extract_param (gcry_sexp_t sexp,
#                                     const char *path,
#                                     const char *list,
#                                     ...) _GCRY_GCC_ATTR_SENTINEL(0);
sub gcry_sexp_extract_param(gcry_sexp                     $sexp # Typedef<gcry_sexp_t>->|gcry_sexp*|
                           ,Str                           $path # const char*
                           ,Str                           $list # const char*
                            ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:522
#/* Allocate a new big integer object, initialize it with 0 and
#   initially allocate memory for a number of at least NBITS. */
#gcry_mpi_t gcry_mpi_new (unsigned int nbits);
sub gcry_mpi_new(uint32 $nbits # unsigned int
                 ) is native(LIB) returns gcry_mpi is export { * }

#-From /usr/include/gcrypt.h:525
#/* Same as gcry_mpi_new() but allocate in "secure" memory. */
#gcry_mpi_t gcry_mpi_snew (unsigned int nbits);
sub gcry_mpi_snew(uint32 $nbits # unsigned int
                  ) is native(LIB) returns gcry_mpi is export { * }

#-From /usr/include/gcrypt.h:528
#/* Release the number A and free all associated resources. */
#void gcry_mpi_release (gcry_mpi_t a);
sub gcry_mpi_release(gcry_mpi $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                     ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:531
#/* Create a new number with the same value as A. */
#gcry_mpi_t gcry_mpi_copy (const gcry_mpi_t a);
sub gcry_mpi_copy(gcry_mpi $a # const Typedef<gcry_mpi_t>->|gcry_mpi*|
                  ) is native(LIB) returns gcry_mpi is export { * }

#-From /usr/include/gcrypt.h:534
#/* Store the big integer value U in W and release U.  */
#void gcry_mpi_snatch (gcry_mpi_t w, gcry_mpi_t u);
sub gcry_mpi_snatch(gcry_mpi                      $w # Typedef<gcry_mpi_t>->|gcry_mpi*|
                   ,gcry_mpi                      $u # Typedef<gcry_mpi_t>->|gcry_mpi*|
                    ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:537
#/* Store the big integer value U in W. */
#gcry_mpi_t gcry_mpi_set (gcry_mpi_t w, const gcry_mpi_t u);
sub gcry_mpi_set(gcry_mpi                      $w # Typedef<gcry_mpi_t>->|gcry_mpi*|
                ,gcry_mpi                      $u # const Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ) is native(LIB) returns gcry_mpi is export { * }

#-From /usr/include/gcrypt.h:540
#/* Store the unsigned integer value U in W. */
#gcry_mpi_t gcry_mpi_set_ui (gcry_mpi_t w, unsigned long u);
sub gcry_mpi_set_ui(gcry_mpi                      $w # Typedef<gcry_mpi_t>->|gcry_mpi*|
                   ,ulong                         $u # long unsigned int
                    ) is native(LIB) returns gcry_mpi is export { * }

#-From /usr/include/gcrypt.h:543
#/* Swap the values of A and B. */
#void gcry_mpi_swap (gcry_mpi_t a, gcry_mpi_t b);
sub gcry_mpi_swap(gcry_mpi                      $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ,gcry_mpi                      $b # Typedef<gcry_mpi_t>->|gcry_mpi*|
                  ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:546
#int gcry_mpi_is_neg (gcry_mpi_t a);
sub gcry_mpi_is_neg(gcry_mpi $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                    ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:549
#/* W = - U */
#void gcry_mpi_neg (gcry_mpi_t w, gcry_mpi_t u);
sub gcry_mpi_neg(gcry_mpi                      $w # Typedef<gcry_mpi_t>->|gcry_mpi*|
                ,gcry_mpi                      $u # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:552
#/* W = [W] */
#void gcry_mpi_abs (gcry_mpi_t w);
sub gcry_mpi_abs(gcry_mpi $w # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:556
#/* Compare the big integer number U and V returning 0 for equality, a
#   positive value for U > V and a negative for U < V. */
#int gcry_mpi_cmp (const gcry_mpi_t u, const gcry_mpi_t v);
sub gcry_mpi_cmp(gcry_mpi                      $u # const Typedef<gcry_mpi_t>->|gcry_mpi*|
                ,gcry_mpi                      $v # const Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:561
#/* Compare the big integer number U with the unsigned integer V
#   returning 0 for equality, a positive value for U > V and a negative
#   for U < V. */
#int gcry_mpi_cmp_ui (const gcry_mpi_t u, unsigned long v);
sub gcry_mpi_cmp_ui(gcry_mpi                      $u # const Typedef<gcry_mpi_t>->|gcry_mpi*|
                   ,ulong                         $v # long unsigned int
                    ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:569
#/* Convert the external representation of an integer stored in BUFFER
#   with a length of BUFLEN into a newly create MPI returned in
#   RET_MPI.  If NSCANNED is not NULL, it will receive the number of
#   bytes actually scanned after a successful operation. */
#gcry_error_t gcry_mpi_scan (gcry_mpi_t *ret_mpi, enum gcry_mpi_format format,
#                            const void *buffer, size_t buflen,
#                            size_t *nscanned);
sub gcry_mpi_scan(Pointer[gcry_mpi]             $ret_mpi # Typedef<gcry_mpi_t>->|gcry_mpi*|*
                 ,int32                         $format # gcry_mpi_format
                 ,Pointer                       $buffer # const void*
                 ,size_t                        $buflen # Typedef<size_t>->|long unsigned int|
                 ,Pointer[size_t]               $nscanned # Typedef<size_t>->|long unsigned int|*
                  ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:579
#/* Convert the big integer A into the external representation
#   described by FORMAT and store it in the provided BUFFER which has
#   been allocated by the user with a size of BUFLEN bytes.  NWRITTEN
#   receives the actual length of the external representation unless it
#   has been passed as NULL. */
#gcry_error_t gcry_mpi_print (enum gcry_mpi_format format,
#                             unsigned char *buffer, size_t buflen,
#                             size_t *nwritten,
#                             const gcry_mpi_t a);
sub gcry_mpi_print(int32                         $format # gcry_mpi_format
                  ,Pointer[uint8]                $buffer # unsigned char*
                  ,size_t                        $buflen # Typedef<size_t>->|long unsigned int|
                  ,Pointer[size_t]               $nwritten # Typedef<size_t>->|long unsigned int|*
                  ,gcry_mpi                      $a # const Typedef<gcry_mpi_t>->|gcry_mpi*|
                   ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:587
#/* Convert the big integer A int the external representation described
#   by FORMAT and store it in a newly allocated buffer which address
#   will be put into BUFFER.  NWRITTEN receives the actual lengths of the
#   external representation. */
#gcry_error_t gcry_mpi_aprint (enum gcry_mpi_format format,
#                              unsigned char **buffer, size_t *nwritten,
#                              const gcry_mpi_t a);
sub gcry_mpi_aprint(int32                         $format # gcry_mpi_format
                   ,Pointer[Pointer[uint8]]       $buffer # unsigned char**
                   ,Pointer[size_t]               $nwritten # Typedef<size_t>->|long unsigned int|*
                   ,gcry_mpi                      $a # const Typedef<gcry_mpi_t>->|gcry_mpi*|
                    ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:593
#/* Dump the value of A in a format suitable for debugging to
#   Libgcrypt's logging stream.  Note that one leading space but no
#   trailing space or linefeed will be printed.  It is okay to pass
#   NULL for A. */
#void gcry_mpi_dump (const gcry_mpi_t a);
sub gcry_mpi_dump(gcry_mpi $a # const Typedef<gcry_mpi_t>->|gcry_mpi*|
                  ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:597
#/* W = U + V.  */
#void gcry_mpi_add (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v);
sub gcry_mpi_add(gcry_mpi                      $w # Typedef<gcry_mpi_t>->|gcry_mpi*|
                ,gcry_mpi                      $u # Typedef<gcry_mpi_t>->|gcry_mpi*|
                ,gcry_mpi                      $v # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:600
#/* W = U + V.  V is an unsigned integer. */
#void gcry_mpi_add_ui (gcry_mpi_t w, gcry_mpi_t u, unsigned long v);
sub gcry_mpi_add_ui(gcry_mpi                      $w # Typedef<gcry_mpi_t>->|gcry_mpi*|
                   ,gcry_mpi                      $u # Typedef<gcry_mpi_t>->|gcry_mpi*|
                   ,ulong                         $v # long unsigned int
                    ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:603
#/* W = U + V mod M. */
#void gcry_mpi_addm (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m);
sub gcry_mpi_addm(gcry_mpi                      $w # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ,gcry_mpi                      $u # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ,gcry_mpi                      $v # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ,gcry_mpi                      $m # Typedef<gcry_mpi_t>->|gcry_mpi*|
                  ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:606
#/* W = U - V. */
#void gcry_mpi_sub (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v);
sub gcry_mpi_sub(gcry_mpi                      $w # Typedef<gcry_mpi_t>->|gcry_mpi*|
                ,gcry_mpi                      $u # Typedef<gcry_mpi_t>->|gcry_mpi*|
                ,gcry_mpi                      $v # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:609
#/* W = U - V.  V is an unsigned integer. */
#void gcry_mpi_sub_ui (gcry_mpi_t w, gcry_mpi_t u, unsigned long v );
sub gcry_mpi_sub_ui(gcry_mpi                      $w # Typedef<gcry_mpi_t>->|gcry_mpi*|
                   ,gcry_mpi                      $u # Typedef<gcry_mpi_t>->|gcry_mpi*|
                   ,ulong                         $v # long unsigned int
                    ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:612
#/* W = U - V mod M */
#void gcry_mpi_subm (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m);
sub gcry_mpi_subm(gcry_mpi                      $w # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ,gcry_mpi                      $u # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ,gcry_mpi                      $v # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ,gcry_mpi                      $m # Typedef<gcry_mpi_t>->|gcry_mpi*|
                  ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:615
#/* W = U * V. */
#void gcry_mpi_mul (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v);
sub gcry_mpi_mul(gcry_mpi                      $w # Typedef<gcry_mpi_t>->|gcry_mpi*|
                ,gcry_mpi                      $u # Typedef<gcry_mpi_t>->|gcry_mpi*|
                ,gcry_mpi                      $v # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:618
#/* W = U * V.  V is an unsigned integer. */
#void gcry_mpi_mul_ui (gcry_mpi_t w, gcry_mpi_t u, unsigned long v );
sub gcry_mpi_mul_ui(gcry_mpi                      $w # Typedef<gcry_mpi_t>->|gcry_mpi*|
                   ,gcry_mpi                      $u # Typedef<gcry_mpi_t>->|gcry_mpi*|
                   ,ulong                         $v # long unsigned int
                    ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:621
#/* W = U * V mod M. */
#void gcry_mpi_mulm (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, gcry_mpi_t m);
sub gcry_mpi_mulm(gcry_mpi                      $w # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ,gcry_mpi                      $u # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ,gcry_mpi                      $v # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ,gcry_mpi                      $m # Typedef<gcry_mpi_t>->|gcry_mpi*|
                  ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:624
#/* W = U * (2 ^ CNT). */
#void gcry_mpi_mul_2exp (gcry_mpi_t w, gcry_mpi_t u, unsigned long cnt);
sub gcry_mpi_mul_2exp(gcry_mpi                      $w # Typedef<gcry_mpi_t>->|gcry_mpi*|
                     ,gcry_mpi                      $u # Typedef<gcry_mpi_t>->|gcry_mpi*|
                     ,ulong                         $cnt # long unsigned int
                      ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:629
#/* Q = DIVIDEND / DIVISOR, R = DIVIDEND % DIVISOR,
#   Q or R may be passed as NULL.  ROUND should be negative or 0. */
#void gcry_mpi_div (gcry_mpi_t q, gcry_mpi_t r,
#                   gcry_mpi_t dividend, gcry_mpi_t divisor, int round);
sub gcry_mpi_div(gcry_mpi                      $q # Typedef<gcry_mpi_t>->|gcry_mpi*|
                ,gcry_mpi                      $r # Typedef<gcry_mpi_t>->|gcry_mpi*|
                ,gcry_mpi                      $dividend # Typedef<gcry_mpi_t>->|gcry_mpi*|
                ,gcry_mpi                      $divisor # Typedef<gcry_mpi_t>->|gcry_mpi*|
                ,int32                         $round # int
                 ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:632
#/* R = DIVIDEND % DIVISOR */
#void gcry_mpi_mod (gcry_mpi_t r, gcry_mpi_t dividend, gcry_mpi_t divisor);
sub gcry_mpi_mod(gcry_mpi                      $r # Typedef<gcry_mpi_t>->|gcry_mpi*|
                ,gcry_mpi                      $dividend # Typedef<gcry_mpi_t>->|gcry_mpi*|
                ,gcry_mpi                      $divisor # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:637
#/* W = B ^ E mod M. */
#void gcry_mpi_powm (gcry_mpi_t w,
#                    const gcry_mpi_t b, const gcry_mpi_t e,
#                    const gcry_mpi_t m);
sub gcry_mpi_powm(gcry_mpi                      $w # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ,gcry_mpi                      $b # const Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ,gcry_mpi                      $e # const Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ,gcry_mpi                      $m # const Typedef<gcry_mpi_t>->|gcry_mpi*|
                  ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:641
#/* Set G to the greatest common divisor of A and B.
#   Return true if the G is 1. */
#int gcry_mpi_gcd (gcry_mpi_t g, gcry_mpi_t a, gcry_mpi_t b);
sub gcry_mpi_gcd(gcry_mpi                      $g # Typedef<gcry_mpi_t>->|gcry_mpi*|
                ,gcry_mpi                      $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                ,gcry_mpi                      $b # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:645
#/* Set X to the multiplicative inverse of A mod M.
#   Return true if the value exists. */
#int gcry_mpi_invm (gcry_mpi_t x, gcry_mpi_t a, gcry_mpi_t m);
sub gcry_mpi_invm(gcry_mpi                      $x # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ,gcry_mpi                      $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                 ,gcry_mpi                      $m # Typedef<gcry_mpi_t>->|gcry_mpi*|
                  ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:648
#/* Create a new point object.  NBITS is usually 0.  */
#gcry_mpi_point_t gcry_mpi_point_new (unsigned int nbits);
sub gcry_mpi_point_new(uint32 $nbits # unsigned int
                       ) is native(LIB) returns gcry_mpi_point is export { * }

#-From /usr/include/gcrypt.h:651
#/* Release the object POINT.  POINT may be NULL. */
#void gcry_mpi_point_release (gcry_mpi_point_t point);
sub gcry_mpi_point_release(gcry_mpi_point $point # Typedef<gcry_mpi_point_t>->|gcry_mpi_point*|
                           ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:655
#/* Store the projective coordinates from POINT into X, Y, and Z.  */
#void gcry_mpi_point_get (gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_t z,
#                         gcry_mpi_point_t point);
sub gcry_mpi_point_get(gcry_mpi                      $x # Typedef<gcry_mpi_t>->|gcry_mpi*|
                      ,gcry_mpi                      $y # Typedef<gcry_mpi_t>->|gcry_mpi*|
                      ,gcry_mpi                      $z # Typedef<gcry_mpi_t>->|gcry_mpi*|
                      ,gcry_mpi_point                $point # Typedef<gcry_mpi_point_t>->|gcry_mpi_point*|
                       ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:660
#/* Store the projective coordinates from POINT into X, Y, and Z and
#   release POINT.  */
#void gcry_mpi_point_snatch_get (gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_t z,
#                                gcry_mpi_point_t point);
sub gcry_mpi_point_snatch_get(gcry_mpi                      $x # Typedef<gcry_mpi_t>->|gcry_mpi*|
                             ,gcry_mpi                      $y # Typedef<gcry_mpi_t>->|gcry_mpi*|
                             ,gcry_mpi                      $z # Typedef<gcry_mpi_t>->|gcry_mpi*|
                             ,gcry_mpi_point                $point # Typedef<gcry_mpi_point_t>->|gcry_mpi_point*|
                              ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:664
#/* Store the projective coordinates X, Y, and Z into POINT.  */
#gcry_mpi_point_t gcry_mpi_point_set (gcry_mpi_point_t point,
#                                     gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_t z);
sub gcry_mpi_point_set(gcry_mpi_point                $point # Typedef<gcry_mpi_point_t>->|gcry_mpi_point*|
                      ,gcry_mpi                      $x # Typedef<gcry_mpi_t>->|gcry_mpi*|
                      ,gcry_mpi                      $y # Typedef<gcry_mpi_t>->|gcry_mpi*|
                      ,gcry_mpi                      $z # Typedef<gcry_mpi_t>->|gcry_mpi*|
                       ) is native(LIB) returns gcry_mpi_point is export { * }

#-From /usr/include/gcrypt.h:670
#/* Store the projective coordinates X, Y, and Z into POINT and release
#   X, Y, and Z.  */
#gcry_mpi_point_t gcry_mpi_point_snatch_set (gcry_mpi_point_t point,
#                                            gcry_mpi_t x, gcry_mpi_t y,
#                                            gcry_mpi_t z);
sub gcry_mpi_point_snatch_set(gcry_mpi_point                $point # Typedef<gcry_mpi_point_t>->|gcry_mpi_point*|
                             ,gcry_mpi                      $x # Typedef<gcry_mpi_t>->|gcry_mpi*|
                             ,gcry_mpi                      $y # Typedef<gcry_mpi_t>->|gcry_mpi*|
                             ,gcry_mpi                      $z # Typedef<gcry_mpi_t>->|gcry_mpi*|
                              ) is native(LIB) returns gcry_mpi_point is export { * }

#-From /usr/include/gcrypt.h:675
#/* Allocate a new context for elliptic curve operations based on the
#   parameters given by KEYPARAM or using CURVENAME.  */
#gpg_error_t gcry_mpi_ec_new (gcry_ctx_t *r_ctx,
#                             gcry_sexp_t keyparam, const char *curvename);
sub gcry_mpi_ec_new(Pointer[gcry_context]         $r_ctx # Typedef<gcry_ctx_t>->|gcry_context*|*
                   ,gcry_sexp                     $keyparam # Typedef<gcry_sexp_t>->|gcry_sexp*|
                   ,Str                           $curvename # const char*
                    ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:678
#/* Get a named MPI from an elliptic curve context.  */
#gcry_mpi_t gcry_mpi_ec_get_mpi (const char *name, gcry_ctx_t ctx, int copy);
sub gcry_mpi_ec_get_mpi(Str                           $name # const char*
                       ,gcry_context                  $ctx # Typedef<gcry_ctx_t>->|gcry_context*|
                       ,int32                         $copy # int
                        ) is native(LIB) returns gcry_mpi is export { * }

#-From /usr/include/gcrypt.h:682
#/* Get a named point from an elliptic curve context.  */
#gcry_mpi_point_t gcry_mpi_ec_get_point (const char *name,
#                                        gcry_ctx_t ctx, int copy);
sub gcry_mpi_ec_get_point(Str                           $name # const char*
                         ,gcry_context                  $ctx # Typedef<gcry_ctx_t>->|gcry_context*|
                         ,int32                         $copy # int
                          ) is native(LIB) returns gcry_mpi_point is export { * }

#-From /usr/include/gcrypt.h:686
#/* Store a named MPI into an elliptic curve context.  */
#gpg_error_t gcry_mpi_ec_set_mpi (const char *name, gcry_mpi_t newvalue,
#                                 gcry_ctx_t ctx);
sub gcry_mpi_ec_set_mpi(Str                           $name # const char*
                       ,gcry_mpi                      $newvalue # Typedef<gcry_mpi_t>->|gcry_mpi*|
                       ,gcry_context                  $ctx # Typedef<gcry_ctx_t>->|gcry_context*|
                        ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:690
#/* Store a named point into an elliptic curve context.  */
#gpg_error_t gcry_mpi_ec_set_point (const char *name, gcry_mpi_point_t newvalue,
#                                   gcry_ctx_t ctx);
sub gcry_mpi_ec_set_point(Str                           $name # const char*
                         ,gcry_mpi_point                $newvalue # Typedef<gcry_mpi_point_t>->|gcry_mpi_point*|
                         ,gcry_context                  $ctx # Typedef<gcry_ctx_t>->|gcry_context*|
                          ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:694
#/* Store the affine coordinates of POINT into X and Y.  */
#int gcry_mpi_ec_get_affine (gcry_mpi_t x, gcry_mpi_t y, gcry_mpi_point_t point,
#                            gcry_ctx_t ctx);
sub gcry_mpi_ec_get_affine(gcry_mpi                      $x # Typedef<gcry_mpi_t>->|gcry_mpi*|
                          ,gcry_mpi                      $y # Typedef<gcry_mpi_t>->|gcry_mpi*|
                          ,gcry_mpi_point                $point # Typedef<gcry_mpi_point_t>->|gcry_mpi_point*|
                          ,gcry_context                  $ctx # Typedef<gcry_ctx_t>->|gcry_context*|
                           ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:697
#/* W = 2 * U.  */
#void gcry_mpi_ec_dup (gcry_mpi_point_t w, gcry_mpi_point_t u, gcry_ctx_t ctx);
sub gcry_mpi_ec_dup(gcry_mpi_point                $w # Typedef<gcry_mpi_point_t>->|gcry_mpi_point*|
                   ,gcry_mpi_point                $u # Typedef<gcry_mpi_point_t>->|gcry_mpi_point*|
                   ,gcry_context                  $ctx # Typedef<gcry_ctx_t>->|gcry_context*|
                    ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:701
#/* W = U + V.  */
#void gcry_mpi_ec_add (gcry_mpi_point_t w,
#                      gcry_mpi_point_t u, gcry_mpi_point_t v, gcry_ctx_t ctx);
sub gcry_mpi_ec_add(gcry_mpi_point                $w # Typedef<gcry_mpi_point_t>->|gcry_mpi_point*|
                   ,gcry_mpi_point                $u # Typedef<gcry_mpi_point_t>->|gcry_mpi_point*|
                   ,gcry_mpi_point                $v # Typedef<gcry_mpi_point_t>->|gcry_mpi_point*|
                   ,gcry_context                  $ctx # Typedef<gcry_ctx_t>->|gcry_context*|
                    ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:705
#/* W = N * U.  */
#void gcry_mpi_ec_mul (gcry_mpi_point_t w, gcry_mpi_t n, gcry_mpi_point_t u,
#                      gcry_ctx_t ctx);
sub gcry_mpi_ec_mul(gcry_mpi_point                $w # Typedef<gcry_mpi_point_t>->|gcry_mpi_point*|
                   ,gcry_mpi                      $n # Typedef<gcry_mpi_t>->|gcry_mpi*|
                   ,gcry_mpi_point                $u # Typedef<gcry_mpi_point_t>->|gcry_mpi_point*|
                   ,gcry_context                  $ctx # Typedef<gcry_ctx_t>->|gcry_context*|
                    ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:708
#/* Return true if POINT is on the curve described by CTX.  */
#int gcry_mpi_ec_curve_point (gcry_mpi_point_t w, gcry_ctx_t ctx);
sub gcry_mpi_ec_curve_point(gcry_mpi_point                $w # Typedef<gcry_mpi_point_t>->|gcry_mpi_point*|
                           ,gcry_context                  $ctx # Typedef<gcry_ctx_t>->|gcry_context*|
                            ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:711
#/* Return the number of bits required to represent A. */
#unsigned int gcry_mpi_get_nbits (gcry_mpi_t a);
sub gcry_mpi_get_nbits(gcry_mpi $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                       ) is native(LIB) returns uint32 is export { * }

#-From /usr/include/gcrypt.h:714
#/* Return true when bit number N (counting from 0) is set in A. */
#int      gcry_mpi_test_bit (gcry_mpi_t a, unsigned int n);
sub gcry_mpi_test_bit(gcry_mpi                      $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                     ,uint32                        $n # unsigned int
                      ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:717
#/* Set bit number N in A. */
#void     gcry_mpi_set_bit (gcry_mpi_t a, unsigned int n);
sub gcry_mpi_set_bit(gcry_mpi                      $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                    ,uint32                        $n # unsigned int
                     ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:720
#/* Clear bit number N in A. */
#void     gcry_mpi_clear_bit (gcry_mpi_t a, unsigned int n);
sub gcry_mpi_clear_bit(gcry_mpi                      $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                      ,uint32                        $n # unsigned int
                       ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:723
#/* Set bit number N in A and clear all bits greater than N. */
#void     gcry_mpi_set_highbit (gcry_mpi_t a, unsigned int n);
sub gcry_mpi_set_highbit(gcry_mpi                      $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                        ,uint32                        $n # unsigned int
                         ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:726
#/* Clear bit number N in A and all bits greater than N. */
#void     gcry_mpi_clear_highbit (gcry_mpi_t a, unsigned int n);
sub gcry_mpi_clear_highbit(gcry_mpi                      $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                          ,uint32                        $n # unsigned int
                           ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:729
#/* Shift the value of A by N bits to the right and store the result in X. */
#void     gcry_mpi_rshift (gcry_mpi_t x, gcry_mpi_t a, unsigned int n);
sub gcry_mpi_rshift(gcry_mpi                      $x # Typedef<gcry_mpi_t>->|gcry_mpi*|
                   ,gcry_mpi                      $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                   ,uint32                        $n # unsigned int
                    ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:732
#/* Shift the value of A by N bits to the left and store the result in X. */
#void     gcry_mpi_lshift (gcry_mpi_t x, gcry_mpi_t a, unsigned int n);
sub gcry_mpi_lshift(gcry_mpi                      $x # Typedef<gcry_mpi_t>->|gcry_mpi*|
                   ,gcry_mpi                      $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                   ,uint32                        $n # unsigned int
                    ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:738
#/* Store NBITS of the value P points to in A and mark A as an opaque
#   value.  On success A received the the ownership of the value P.
#   WARNING: Never use an opaque MPI for anything thing else than
#   gcry_mpi_release, gcry_mpi_get_opaque. */
#gcry_mpi_t gcry_mpi_set_opaque (gcry_mpi_t a, void *p, unsigned int nbits);
sub gcry_mpi_set_opaque(gcry_mpi                      $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                       ,Pointer                       $p # void*
                       ,uint32                        $nbits # unsigned int
                        ) is native(LIB) returns gcry_mpi is export { * }

#-From /usr/include/gcrypt.h:745
#/* Store NBITS of the value P points to in A and mark A as an opaque
#   value.  The function takes a copy of the provided value P.
#   WARNING: Never use an opaque MPI for anything thing else than
#   gcry_mpi_release, gcry_mpi_get_opaque. */
#gcry_mpi_t gcry_mpi_set_opaque_copy (gcry_mpi_t a,
#                                     const void *p, unsigned int nbits);
sub gcry_mpi_set_opaque_copy(gcry_mpi                      $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                            ,Pointer                       $p # const void*
                            ,uint32                        $nbits # unsigned int
                             ) is native(LIB) returns gcry_mpi is export { * }

#-From /usr/include/gcrypt.h:750
#/* Return a pointer to an opaque value stored in A and return its size
#   in NBITS.  Note that the returned pointer is still owned by A and
#   that the function should never be used for an non-opaque MPI. */
#void *gcry_mpi_get_opaque (gcry_mpi_t a, unsigned int *nbits);
sub gcry_mpi_get_opaque(gcry_mpi                      $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                       ,Pointer[uint32]               $nbits # unsigned int*
                        ) is native(LIB) returns Pointer is export { * }

#-From /usr/include/gcrypt.h:755
#/* Set the FLAG for the big integer A.  Currently only the flag
#   GCRYMPI_FLAG_SECURE is allowed to convert A into an big intger
#   stored in "secure" memory. */
#void gcry_mpi_set_flag (gcry_mpi_t a, enum gcry_mpi_flag flag);
sub gcry_mpi_set_flag(gcry_mpi                      $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                     ,int32                         $flag # gcry_mpi_flag
                      ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:759
#/* Clear FLAG for the big integer A.  Note that this function is
#   currently useless as no flags are allowed. */
#void gcry_mpi_clear_flag (gcry_mpi_t a, enum gcry_mpi_flag flag);
sub gcry_mpi_clear_flag(gcry_mpi                      $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                       ,int32                         $flag # gcry_mpi_flag
                        ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:762
#/* Return true if the FLAG is set for A. */
#int gcry_mpi_get_flag (gcry_mpi_t a, enum gcry_mpi_flag flag);
sub gcry_mpi_get_flag(gcry_mpi                      $a # Typedef<gcry_mpi_t>->|gcry_mpi*|
                     ,int32                         $flag # gcry_mpi_flag
                      ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:765
#/* Private function - do not use.  */
#gcry_mpi_t _gcry_mpi_get_const (int no);
sub _gcry_mpi_get_const(int32 $no # int
                        ) is native(LIB) returns gcry_mpi is export { * }

#-From /usr/include/gcrypt.h:925
#/* Create a handle for algorithm ALGO to be used in MODE.  FLAGS may
#   be given as an bitwise OR of the gcry_cipher_flags values. */
#gcry_error_t gcry_cipher_open (gcry_cipher_hd_t *handle,
#                              int algo, int mode, unsigned int flags);
sub gcry_cipher_open(Pointer[gcry_cipher_handle]   $handle # Typedef<gcry_cipher_hd_t>->|gcry_cipher_handle*|*
                    ,int32                         $algo # int
                    ,int32                         $mode # int
                    ,uint32                        $flags # unsigned int
                     ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:928
#/* Close the cioher handle H and release all resource. */
#void gcry_cipher_close (gcry_cipher_hd_t h);
sub gcry_cipher_close(gcry_cipher_handle $h # Typedef<gcry_cipher_hd_t>->|gcry_cipher_handle*|
                      ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:932
#/* Perform various operations on the cipher object H. */
#gcry_error_t gcry_cipher_ctl (gcry_cipher_hd_t h, int cmd, void *buffer,
#                             size_t buflen);
sub gcry_cipher_ctl(gcry_cipher_handle            $h # Typedef<gcry_cipher_hd_t>->|gcry_cipher_handle*|
                   ,int32                         $cmd # int
                   ,Pointer                       $buffer # void*
                   ,size_t                        $buflen # Typedef<size_t>->|long unsigned int|
                    ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:936
#/* Retrieve various information about the cipher object H. */
#gcry_error_t gcry_cipher_info (gcry_cipher_hd_t h, int what, void *buffer,
#                              size_t *nbytes);
sub gcry_cipher_info(gcry_cipher_handle            $h # Typedef<gcry_cipher_hd_t>->|gcry_cipher_handle*|
                    ,int32                         $what # int
                    ,Pointer                       $buffer # void*
                    ,Pointer[size_t]               $nbytes # Typedef<size_t>->|long unsigned int|*
                     ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:940
#/* Retrieve various information about the cipher algorithm ALGO. */
#gcry_error_t gcry_cipher_algo_info (int algo, int what, void *buffer,
#                                   size_t *nbytes);
sub gcry_cipher_algo_info(int32                         $algo # int
                         ,int32                         $what # int
                         ,Pointer                       $buffer # void*
                         ,Pointer[size_t]               $nbytes # Typedef<size_t>->|long unsigned int|*
                          ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:945
#/* Map the cipher algorithm whose ID is contained in ALGORITHM to a
#   string representation of the algorithm name.  For unknown algorithm
#   IDs this function returns "?".  */
#const char *gcry_cipher_algo_name (int algorithm) _GCRY_GCC_ATTR_PURE;
sub gcry_cipher_algo_name(int32 $algorithm # int
                          ) is native(LIB) returns Str is export { * }

#-From /usr/include/gcrypt.h:949
#/* Map the algorithm name NAME to an cipher algorithm ID.  Return 0 if
#   the algorithm name is not known. */
#int gcry_cipher_map_name (const char *name) _GCRY_GCC_ATTR_PURE;
sub gcry_cipher_map_name(Str $name # const char*
                         ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:954
#/* Given an ASN.1 object identifier in standard IETF dotted decimal
#   format in STRING, return the encryption mode associated with that
#   OID or 0 if not known or applicable. */
#int gcry_cipher_mode_from_oid (const char *string) _GCRY_GCC_ATTR_PURE;
sub gcry_cipher_mode_from_oid(Str $string # const char*
                              ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:962
#/* Encrypt the plaintext of size INLEN in IN using the cipher handle H
#   into the buffer OUT which has an allocated length of OUTSIZE.  For
#   most algorithms it is possible to pass NULL for in and 0 for INLEN
#   and do a in-place decryption of the data provided in OUT.  */
#gcry_error_t gcry_cipher_encrypt (gcry_cipher_hd_t h,
#                                  void *out, size_t outsize,
#                                  const void *in, size_t inlen);
sub gcry_cipher_encrypt(gcry_cipher_handle            $h # Typedef<gcry_cipher_hd_t>->|gcry_cipher_handle*|
                       ,Pointer                       $out # void*
                       ,size_t                        $outsize # Typedef<size_t>->|long unsigned int|
                       ,Pointer                       $in # const void*
                       ,size_t                        $inlen # Typedef<size_t>->|long unsigned int|
                        ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:967
#/* The counterpart to gcry_cipher_encrypt.  */
#gcry_error_t gcry_cipher_decrypt (gcry_cipher_hd_t h,
#                                  void *out, size_t outsize,
#                                  const void *in, size_t inlen);
sub gcry_cipher_decrypt(gcry_cipher_handle            $h # Typedef<gcry_cipher_hd_t>->|gcry_cipher_handle*|
                       ,Pointer                       $out # void*
                       ,size_t                        $outsize # Typedef<size_t>->|long unsigned int|
                       ,Pointer                       $in # const void*
                       ,size_t                        $inlen # Typedef<size_t>->|long unsigned int|
                        ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:971
#/* Set KEY of length KEYLEN bytes for the cipher handle HD.  */
#gcry_error_t gcry_cipher_setkey (gcry_cipher_hd_t hd,
#                                 const void *key, size_t keylen);
sub gcry_cipher_setkey(gcry_cipher_handle            $hd # Typedef<gcry_cipher_hd_t>->|gcry_cipher_handle*|
                      ,Pointer                       $key # const void*
                      ,size_t                        $keylen # Typedef<size_t>->|long unsigned int|
                       ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:976
#/* Set initialization vector IV of length IVLEN for the cipher handle HD. */
#gcry_error_t gcry_cipher_setiv (gcry_cipher_hd_t hd,
#                                const void *iv, size_t ivlen);
sub gcry_cipher_setiv(gcry_cipher_handle            $hd # Typedef<gcry_cipher_hd_t>->|gcry_cipher_handle*|
                     ,Pointer                       $iv # const void*
                     ,size_t                        $ivlen # Typedef<size_t>->|long unsigned int|
                      ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:980
#/* Provide additional authentication data for AEAD modes/ciphers.  */
#gcry_error_t gcry_cipher_authenticate (gcry_cipher_hd_t hd, const void *abuf,
#                                       size_t abuflen);
sub gcry_cipher_authenticate(gcry_cipher_handle            $hd # Typedef<gcry_cipher_hd_t>->|gcry_cipher_handle*|
                            ,Pointer                       $abuf # const void*
                            ,size_t                        $abuflen # Typedef<size_t>->|long unsigned int|
                             ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:984
#/* Get authentication tag for AEAD modes/ciphers.  */
#gcry_error_t gcry_cipher_gettag (gcry_cipher_hd_t hd, void *outtag,
#                                 size_t taglen);
sub gcry_cipher_gettag(gcry_cipher_handle            $hd # Typedef<gcry_cipher_hd_t>->|gcry_cipher_handle*|
                      ,Pointer                       $outtag # void*
                      ,size_t                        $taglen # Typedef<size_t>->|long unsigned int|
                       ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:988
#/* Check authentication tag for AEAD modes/ciphers.  */
#gcry_error_t gcry_cipher_checktag (gcry_cipher_hd_t hd, const void *intag,
#                                   size_t taglen);
sub gcry_cipher_checktag(gcry_cipher_handle            $hd # Typedef<gcry_cipher_hd_t>->|gcry_cipher_handle*|
                        ,Pointer                       $intag # const void*
                        ,size_t                        $taglen # Typedef<size_t>->|long unsigned int|
                         ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1004
#/* Set counter for CTR mode.  (CTR,CTRLEN) must denote a buffer of
#   block size length, or (NULL,0) to set the CTR to the all-zero block. */
#gpg_error_t gcry_cipher_setctr (gcry_cipher_hd_t hd,
#                                const void *ctr, size_t ctrlen);
sub gcry_cipher_setctr(gcry_cipher_handle            $hd # Typedef<gcry_cipher_hd_t>->|gcry_cipher_handle*|
                      ,Pointer                       $ctr # const void*
                      ,size_t                        $ctrlen # Typedef<size_t>->|long unsigned int|
                       ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1007
#/* Retrieve the key length in bytes used with algorithm A. */
#size_t gcry_cipher_get_algo_keylen (int algo);
sub gcry_cipher_get_algo_keylen(int32 $algo # int
                                ) is native(LIB) returns size_t is export { * }

#-From /usr/include/gcrypt.h:1010
#/* Retrieve the block length in bytes used with algorithm A. */
#size_t gcry_cipher_get_algo_blklen (int algo);
sub gcry_cipher_get_algo_blklen(int32 $algo # int
                                ) is native(LIB) returns size_t is export { * }

#-From /usr/include/gcrypt.h:1051
#/* Encrypt the DATA using the public key PKEY and store the result as
#   a newly created S-expression at RESULT. */
#gcry_error_t gcry_pk_encrypt (gcry_sexp_t *result,
#                              gcry_sexp_t data, gcry_sexp_t pkey);
sub gcry_pk_encrypt(Pointer[gcry_sexp]            $result # Typedef<gcry_sexp_t>->|gcry_sexp*|*
                   ,gcry_sexp                     $data # Typedef<gcry_sexp_t>->|gcry_sexp*|
                   ,gcry_sexp                     $pkey # Typedef<gcry_sexp_t>->|gcry_sexp*|
                    ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1056
#/* Decrypt the DATA using the private key SKEY and store the result as
#   a newly created S-expression at RESULT. */
#gcry_error_t gcry_pk_decrypt (gcry_sexp_t *result,
#                              gcry_sexp_t data, gcry_sexp_t skey);
sub gcry_pk_decrypt(Pointer[gcry_sexp]            $result # Typedef<gcry_sexp_t>->|gcry_sexp*|*
                   ,gcry_sexp                     $data # Typedef<gcry_sexp_t>->|gcry_sexp*|
                   ,gcry_sexp                     $skey # Typedef<gcry_sexp_t>->|gcry_sexp*|
                    ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1061
#/* Sign the DATA using the private key SKEY and store the result as
#   a newly created S-expression at RESULT. */
#gcry_error_t gcry_pk_sign (gcry_sexp_t *result,
#                           gcry_sexp_t data, gcry_sexp_t skey);
sub gcry_pk_sign(Pointer[gcry_sexp]            $result # Typedef<gcry_sexp_t>->|gcry_sexp*|*
                ,gcry_sexp                     $data # Typedef<gcry_sexp_t>->|gcry_sexp*|
                ,gcry_sexp                     $skey # Typedef<gcry_sexp_t>->|gcry_sexp*|
                 ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1065
#/* Check the signature SIGVAL on DATA using the public key PKEY. */
#gcry_error_t gcry_pk_verify (gcry_sexp_t sigval,
#                             gcry_sexp_t data, gcry_sexp_t pkey);
sub gcry_pk_verify(gcry_sexp                     $sigval # Typedef<gcry_sexp_t>->|gcry_sexp*|
                  ,gcry_sexp                     $data # Typedef<gcry_sexp_t>->|gcry_sexp*|
                  ,gcry_sexp                     $pkey # Typedef<gcry_sexp_t>->|gcry_sexp*|
                   ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1068
#/* Check that private KEY is sane. */
#gcry_error_t gcry_pk_testkey (gcry_sexp_t key);
sub gcry_pk_testkey(gcry_sexp $key # Typedef<gcry_sexp_t>->|gcry_sexp*|
                    ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1073
#/* Generate a new key pair according to the parameters given in
#   S_PARMS.  The new key pair is returned in as an S-expression in
#   R_KEY. */
#gcry_error_t gcry_pk_genkey (gcry_sexp_t *r_key, gcry_sexp_t s_parms);
sub gcry_pk_genkey(Pointer[gcry_sexp]            $r_key # Typedef<gcry_sexp_t>->|gcry_sexp*|*
                  ,gcry_sexp                     $s_parms # Typedef<gcry_sexp_t>->|gcry_sexp*|
                   ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1076
#/* Catch all function for miscellaneous operations. */
#gcry_error_t gcry_pk_ctl (int cmd, void *buffer, size_t buflen);
sub gcry_pk_ctl(int32                         $cmd # int
               ,Pointer                       $buffer # void*
               ,size_t                        $buflen # Typedef<size_t>->|long unsigned int|
                ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1080
#/* Retrieve information about the public key algorithm ALGO. */
#gcry_error_t gcry_pk_algo_info (int algo, int what,
#                                void *buffer, size_t *nbytes);
sub gcry_pk_algo_info(int32                         $algo # int
                     ,int32                         $what # int
                     ,Pointer                       $buffer # void*
                     ,Pointer[size_t]               $nbytes # Typedef<size_t>->|long unsigned int|*
                      ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1085
#/* Map the public key algorithm whose ID is contained in ALGORITHM to
#   a string representation of the algorithm name.  For unknown
#   algorithm IDs this functions returns "?". */
#const char *gcry_pk_algo_name (int algorithm) _GCRY_GCC_ATTR_PURE;
sub gcry_pk_algo_name(int32 $algorithm # int
                      ) is native(LIB) returns Str is export { * }

#-From /usr/include/gcrypt.h:1089
#/* Map the algorithm NAME to a public key algorithm Id.  Return 0 if
#   the algorithm name is not known. */
#int gcry_pk_map_name (const char* name) _GCRY_GCC_ATTR_PURE;
sub gcry_pk_map_name(Str $name # const char*
                     ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:1093
#/* Return what is commonly referred as the key length for the given
#   public or private KEY.  */
#unsigned int gcry_pk_get_nbits (gcry_sexp_t key) _GCRY_GCC_ATTR_PURE;
sub gcry_pk_get_nbits(gcry_sexp $key # Typedef<gcry_sexp_t>->|gcry_sexp*|
                      ) is native(LIB) returns uint32 is export { * }

#-From /usr/include/gcrypt.h:1097
#/* Return the so called KEYGRIP which is the SHA-1 hash of the public
#   key parameters expressed in a way depending on the algorithm.  */
#unsigned char *gcry_pk_get_keygrip (gcry_sexp_t key, unsigned char *array);
sub gcry_pk_get_keygrip(gcry_sexp                     $key # Typedef<gcry_sexp_t>->|gcry_sexp*|
                       ,Pointer[uint8]                $array # unsigned char*
                        ) is native(LIB) returns Pointer[uint8] is export { * }

#-From /usr/include/gcrypt.h:1101
#/* Return the name of the curve matching KEY.  */
#const char *gcry_pk_get_curve (gcry_sexp_t key, int iterator,
#                               unsigned int *r_nbits);
sub gcry_pk_get_curve(gcry_sexp                     $key # Typedef<gcry_sexp_t>->|gcry_sexp*|
                     ,int32                         $iterator # int
                     ,Pointer[uint32]               $r_nbits # unsigned int*
                      ) is native(LIB) returns Str is export { * }

#-From /usr/include/gcrypt.h:1105
#/* Return an S-expression with the parameters of the named ECC curve
#   NAME.  ALGO must be set to an ECC algorithm.  */
#gcry_sexp_t gcry_pk_get_param (int algo, const char *name);
sub gcry_pk_get_param(int32                         $algo # int
                     ,Str                           $name # const char*
                      ) is native(LIB) returns gcry_sexp is export { * }

#-From /usr/include/gcrypt.h:1113
#/* Return an S-expression representing the context CTX.  */
#gcry_error_t gcry_pubkey_get_sexp (gcry_sexp_t *r_sexp,
#                                   int mode, gcry_ctx_t ctx);
sub gcry_pubkey_get_sexp(Pointer[gcry_sexp]            $r_sexp # Typedef<gcry_sexp_t>->|gcry_sexp*|*
                        ,int32                         $mode # int
                        ,gcry_context                  $ctx # Typedef<gcry_ctx_t>->|gcry_context*|
                         ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1185
#/* Create a message digest object for algorithm ALGO.  FLAGS may be
#   given as an bitwise OR of the gcry_md_flags values.  ALGO may be
#   given as 0 if the algorithms to be used are later set using
#   gcry_md_enable.  */
#gcry_error_t gcry_md_open (gcry_md_hd_t *h, int algo, unsigned int flags);
sub gcry_md_open(Pointer[gcry_md_handle]       $h # Typedef<gcry_md_hd_t>->|gcry_md_handle*|*
                ,int32                         $algo # int
                ,uint32                        $flags # unsigned int
                 ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1188
#/* Release the message digest object HD.  */
#void gcry_md_close (gcry_md_hd_t hd);
sub gcry_md_close(gcry_md_handle $hd # Typedef<gcry_md_hd_t>->|gcry_md_handle*|
                  ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1191
#/* Add the message digest algorithm ALGO to the digest object HD.  */
#gcry_error_t gcry_md_enable (gcry_md_hd_t hd, int algo);
sub gcry_md_enable(gcry_md_handle                $hd # Typedef<gcry_md_hd_t>->|gcry_md_handle*|
                  ,int32                         $algo # int
                   ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1194
#/* Create a new digest object as an exact copy of the object HD.  */
#gcry_error_t gcry_md_copy (gcry_md_hd_t *bhd, gcry_md_hd_t ahd);
sub gcry_md_copy(Pointer[gcry_md_handle]       $bhd # Typedef<gcry_md_hd_t>->|gcry_md_handle*|*
                ,gcry_md_handle                $ahd # Typedef<gcry_md_hd_t>->|gcry_md_handle*|
                 ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1197
#/* Reset the digest object HD to its initial state.  */
#void gcry_md_reset (gcry_md_hd_t hd);
sub gcry_md_reset(gcry_md_handle $hd # Typedef<gcry_md_hd_t>->|gcry_md_handle*|
                  ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1201
#/* Perform various operations on the digest object HD. */
#gcry_error_t gcry_md_ctl (gcry_md_hd_t hd, int cmd,
#                          void *buffer, size_t buflen);
sub gcry_md_ctl(gcry_md_handle                $hd # Typedef<gcry_md_hd_t>->|gcry_md_handle*|
               ,int32                         $cmd # int
               ,Pointer                       $buffer # void*
               ,size_t                        $buflen # Typedef<size_t>->|long unsigned int|
                ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1206
#/* Pass LENGTH bytes of data in BUFFER to the digest object HD so that
#   it can update the digest values.  This is the actual hash
#   function. */
#void gcry_md_write (gcry_md_hd_t hd, const void *buffer, size_t length);
sub gcry_md_write(gcry_md_handle                $hd # Typedef<gcry_md_hd_t>->|gcry_md_handle*|
                 ,Pointer                       $buffer # const void*
                 ,size_t                        $length # Typedef<size_t>->|long unsigned int|
                  ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1210
#/* Read out the final digest from HD return the digest value for
#   algorithm ALGO. */
#unsigned char *gcry_md_read (gcry_md_hd_t hd, int algo);
sub gcry_md_read(gcry_md_handle                $hd # Typedef<gcry_md_hd_t>->|gcry_md_handle*|
                ,int32                         $algo # int
                 ) is native(LIB) returns Pointer[uint8] is export { * }

#-From /usr/include/gcrypt.h:1218
#/* Convenience function to calculate the hash from the data in BUFFER
#   of size LENGTH using the algorithm ALGO avoiding the creating of a
#   hash object.  The hash is returned in the caller provided buffer
#   DIGEST which must be large enough to hold the digest of the given
#   algorithm. */
#void gcry_md_hash_buffer (int algo, void *digest,
#                          const void *buffer, size_t length);
sub gcry_md_hash_buffer(int32                         $algo # int
                       ,Pointer                       $digest # void*
                       ,Pointer                       $buffer # const void*
                       ,size_t                        $length # Typedef<size_t>->|long unsigned int|
                        ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1222
#/* Convenience function to hash multiple buffers.  */
#gpg_error_t gcry_md_hash_buffers (int algo, unsigned int flags, void *digest,
#                                  const gcry_buffer_t *iov, int iovcnt);
sub gcry_md_hash_buffers(int32                         $algo # int
                        ,uint32                        $flags # unsigned int
                        ,Pointer                       $digest # void*
                        ,gcry_buffer_t                 $iov # const gcry_buffer_t*
                        ,int32                         $iovcnt # int
                         ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1226
#/* Retrieve the algorithm used with HD.  This does not work reliable
#   if more than one algorithm is enabled in HD. */
#int gcry_md_get_algo (gcry_md_hd_t hd);
sub gcry_md_get_algo(gcry_md_handle $hd # Typedef<gcry_md_hd_t>->|gcry_md_handle*|
                     ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:1230
#/* Retrieve the length in bytes of the digest yielded by algorithm
#   ALGO. */
#unsigned int gcry_md_get_algo_dlen (int algo);
sub gcry_md_get_algo_dlen(int32 $algo # int
                          ) is native(LIB) returns uint32 is export { * }

#-From /usr/include/gcrypt.h:1234
#/* Return true if the the algorithm ALGO is enabled in the digest
#   object A. */
#int gcry_md_is_enabled (gcry_md_hd_t a, int algo);
sub gcry_md_is_enabled(gcry_md_handle                $a # Typedef<gcry_md_hd_t>->|gcry_md_handle*|
                      ,int32                         $algo # int
                       ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:1237
#/* Return true if the digest object A is allocated in "secure" memory. */
#int gcry_md_is_secure (gcry_md_hd_t a);
sub gcry_md_is_secure(gcry_md_handle $a # Typedef<gcry_md_hd_t>->|gcry_md_handle*|
                      ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:1241
#/* Retrieve various information about the object H.  */
#gcry_error_t gcry_md_info (gcry_md_hd_t h, int what, void *buffer,
#                          size_t *nbytes);
sub gcry_md_info(gcry_md_handle                $h # Typedef<gcry_md_hd_t>->|gcry_md_handle*|
                ,int32                         $what # int
                ,Pointer                       $buffer # void*
                ,Pointer[size_t]               $nbytes # Typedef<size_t>->|long unsigned int|*
                 ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1245
#/* Retrieve various information about the algorithm ALGO.  */
#gcry_error_t gcry_md_algo_info (int algo, int what, void *buffer,
#                               size_t *nbytes);
sub gcry_md_algo_info(int32                         $algo # int
                     ,int32                         $what # int
                     ,Pointer                       $buffer # void*
                     ,Pointer[size_t]               $nbytes # Typedef<size_t>->|long unsigned int|*
                      ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1250
#/* Map the digest algorithm id ALGO to a string representation of the
#   algorithm name.  For unknown algorithms this function returns
#   "?". */
#const char *gcry_md_algo_name (int algo) _GCRY_GCC_ATTR_PURE;
sub gcry_md_algo_name(int32 $algo # int
                      ) is native(LIB) returns Str is export { * }

#-From /usr/include/gcrypt.h:1254
#/* Map the algorithm NAME to a digest algorithm Id.  Return 0 if
#   the algorithm name is not known. */
#int gcry_md_map_name (const char* name) _GCRY_GCC_ATTR_PURE;
sub gcry_md_map_name(Str $name # const char*
                     ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:1258
#/* For use with the HMAC feature, the set MAC key to the KEY of
#   KEYLEN bytes. */
#gcry_error_t gcry_md_setkey (gcry_md_hd_t hd, const void *key, size_t keylen);
sub gcry_md_setkey(gcry_md_handle                $hd # Typedef<gcry_md_hd_t>->|gcry_md_handle*|
                  ,Pointer                       $key # const void*
                  ,size_t                        $keylen # Typedef<size_t>->|long unsigned int|
                   ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1263
#   named dbgmd-<n>.<suffix> while hashing.  If SUFFIX is NULL,
#   debugging stops and the file will be closed. */
#void gcry_md_debug (gcry_md_hd_t hd, const char *suffix);
sub gcry_md_debug(gcry_md_handle                $hd # Typedef<gcry_md_hd_t>->|gcry_md_handle*|
                 ,Str                           $suffix # const char*
                  ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1353
#/* Create a MAC handle for algorithm ALGO.  FLAGS may be given as an bitwise OR
#   of the gcry_mac_flags values.  CTX maybe NULL or gcry_ctx_t object to be
#   associated with HANDLE.  */
#gcry_error_t gcry_mac_open (gcry_mac_hd_t *handle, int algo,
#                            unsigned int flags, gcry_ctx_t ctx);
sub gcry_mac_open(Pointer[gcry_mac_handle]      $handle # Typedef<gcry_mac_hd_t>->|gcry_mac_handle*|*
                 ,int32                         $algo # int
                 ,uint32                        $flags # unsigned int
                 ,gcry_context                  $ctx # Typedef<gcry_ctx_t>->|gcry_context*|
                  ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1356
#/* Close the MAC handle H and release all resource. */
#void gcry_mac_close (gcry_mac_hd_t h);
sub gcry_mac_close(gcry_mac_handle $h # Typedef<gcry_mac_hd_t>->|gcry_mac_handle*|
                   ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1360
#/* Perform various operations on the MAC object H. */
#gcry_error_t gcry_mac_ctl (gcry_mac_hd_t h, int cmd, void *buffer,
#                           size_t buflen);
sub gcry_mac_ctl(gcry_mac_handle               $h # Typedef<gcry_mac_hd_t>->|gcry_mac_handle*|
                ,int32                         $cmd # int
                ,Pointer                       $buffer # void*
                ,size_t                        $buflen # Typedef<size_t>->|long unsigned int|
                 ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1364
#/* Retrieve various information about the MAC algorithm ALGO. */
#gcry_error_t gcry_mac_algo_info (int algo, int what, void *buffer,
#                                 size_t *nbytes);
sub gcry_mac_algo_info(int32                         $algo # int
                      ,int32                         $what # int
                      ,Pointer                       $buffer # void*
                      ,Pointer[size_t]               $nbytes # Typedef<size_t>->|long unsigned int|*
                       ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1368
#/* Set KEY of length KEYLEN bytes for the MAC handle HD.  */
#gcry_error_t gcry_mac_setkey (gcry_mac_hd_t hd, const void *key,
#                              size_t keylen);
sub gcry_mac_setkey(gcry_mac_handle               $hd # Typedef<gcry_mac_hd_t>->|gcry_mac_handle*|
                   ,Pointer                       $key # const void*
                   ,size_t                        $keylen # Typedef<size_t>->|long unsigned int|
                    ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1372
#/* Set initialization vector IV of length IVLEN for the MAC handle HD. */
#gcry_error_t gcry_mac_setiv (gcry_mac_hd_t hd, const void *iv,
#                             size_t ivlen);
sub gcry_mac_setiv(gcry_mac_handle               $hd # Typedef<gcry_mac_hd_t>->|gcry_mac_handle*|
                  ,Pointer                       $iv # const void*
                  ,size_t                        $ivlen # Typedef<size_t>->|long unsigned int|
                   ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1377
#/* Pass LENGTH bytes of data in BUFFER to the MAC object HD so that
#   it can update the MAC values.  */
#gcry_error_t gcry_mac_write (gcry_mac_hd_t hd, const void *buffer,
#                             size_t length);
sub gcry_mac_write(gcry_mac_handle               $hd # Typedef<gcry_mac_hd_t>->|gcry_mac_handle*|
                  ,Pointer                       $buffer # const void*
                  ,size_t                        $length # Typedef<size_t>->|long unsigned int|
                   ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1380
#/* Read out the final authentication code from the MAC object HD to BUFFER. */
#gcry_error_t gcry_mac_read (gcry_mac_hd_t hd, void *buffer, size_t *buflen);
sub gcry_mac_read(gcry_mac_handle               $hd # Typedef<gcry_mac_hd_t>->|gcry_mac_handle*|
                 ,Pointer                       $buffer # void*
                 ,Pointer[size_t]               $buflen # Typedef<size_t>->|long unsigned int|*
                  ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1384
#/* Verify the final authentication code from the MAC object HD with BUFFER. */
#gcry_error_t gcry_mac_verify (gcry_mac_hd_t hd, const void *buffer,
#                              size_t buflen);
sub gcry_mac_verify(gcry_mac_handle               $hd # Typedef<gcry_mac_hd_t>->|gcry_mac_handle*|
                   ,Pointer                       $buffer # const void*
                   ,size_t                        $buflen # Typedef<size_t>->|long unsigned int|
                    ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1387
#/* Retrieve the length in bytes of the MAC yielded by algorithm ALGO. */
#unsigned int gcry_mac_get_algo_maclen (int algo);
sub gcry_mac_get_algo_maclen(int32 $algo # int
                             ) is native(LIB) returns uint32 is export { * }

#-From /usr/include/gcrypt.h:1390
#/* Retrieve the default key length in bytes used with algorithm A. */
#unsigned int gcry_mac_get_algo_keylen (int algo);
sub gcry_mac_get_algo_keylen(int32 $algo # int
                             ) is native(LIB) returns uint32 is export { * }

#-From /usr/include/gcrypt.h:1395
#/* Map the MAC algorithm whose ID is contained in ALGORITHM to a
#   string representation of the algorithm name.  For unknown algorithm
#   IDs this function returns "?".  */
#const char *gcry_mac_algo_name (int algorithm) _GCRY_GCC_ATTR_PURE;
sub gcry_mac_algo_name(int32 $algorithm # int
                       ) is native(LIB) returns Str is export { * }

#-From /usr/include/gcrypt.h:1399
#/* Map the algorithm name NAME to an MAC algorithm ID.  Return 0 if
#   the algorithm name is not known. */
#int gcry_mac_map_name (const char *name) _GCRY_GCC_ATTR_PURE;
sub gcry_mac_map_name(Str $name # const char*
                      ) is native(LIB) returns int32 is export { * }

#-From /usr/include/gcrypt.h:1432
#/* Derive a key from a passphrase.  */
#gpg_error_t gcry_kdf_derive (const void *passphrase, size_t passphraselen,
#                             int algo, int subalgo,
#                             const void *salt, size_t saltlen,
#                             unsigned long iterations,
#                             size_t keysize, void *keybuffer);
sub gcry_kdf_derive(Pointer                       $passphrase # const void*
                   ,size_t                        $passphraselen # Typedef<size_t>->|long unsigned int|
                   ,int32                         $algo # int
                   ,int32                         $subalgo # int
                   ,Pointer                       $salt # const void*
                   ,size_t                        $saltlen # Typedef<size_t>->|long unsigned int|
                   ,ulong                         $iterations # long unsigned int
                   ,size_t                        $keysize # Typedef<size_t>->|long unsigned int|
                   ,Pointer                       $keybuffer # void*
                    ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1466
#/* Fill BUFFER with LENGTH bytes of random, using random numbers of
#   quality LEVEL. */
#void gcry_randomize (void *buffer, size_t length,
#                     enum gcry_random_level level);
sub gcry_randomize(Pointer                       $buffer # void*
                  ,size_t                        $length # Typedef<size_t>->|long unsigned int|
                  ,int32                         $level # gcry_random_level
                   ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1472
#/* Add the external random from BUFFER with LENGTH bytes into the
#   pool. QUALITY should either be -1 for unknown or in the range of 0
#   to 100 */
#gcry_error_t gcry_random_add_bytes (const void *buffer, size_t length,
#                                    int quality);
sub gcry_random_add_bytes(Pointer                       $buffer # const void*
                         ,size_t                        $length # Typedef<size_t>->|long unsigned int|
                         ,int32                         $quality # int
                          ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1483
#/* Return NBYTES of allocated random using a random numbers of quality
#   LEVEL. */
#void *gcry_random_bytes (size_t nbytes, enum gcry_random_level level)
#                         _GCRY_GCC_ATTR_MALLOC;
sub gcry_random_bytes(size_t                        $nbytes # Typedef<size_t>->|long unsigned int|
                     ,int32                         $level # gcry_random_level
                      ) is native(LIB) returns Pointer is export { * }

#-From /usr/include/gcrypt.h:1489
#/* Return NBYTES of allocated random using a random numbers of quality
#   LEVEL.  The random numbers are created returned in "secure"
#   memory. */
#void *gcry_random_bytes_secure (size_t nbytes, enum gcry_random_level level)
#                                _GCRY_GCC_ATTR_MALLOC;
sub gcry_random_bytes_secure(size_t                        $nbytes # Typedef<size_t>->|long unsigned int|
                            ,int32                         $level # gcry_random_level
                             ) is native(LIB) returns Pointer is export { * }

#-From /usr/include/gcrypt.h:1496
#/* Set the big integer W to a random value of NBITS using a random
#   generator with quality LEVEL.  Note that by using a level of
#   GCRY_WEAK_RANDOM gcry_create_nonce is used internally. */
#void gcry_mpi_randomize (gcry_mpi_t w,
#                         unsigned int nbits, enum gcry_random_level level);
sub gcry_mpi_randomize(gcry_mpi                      $w # Typedef<gcry_mpi_t>->|gcry_mpi*|
                      ,uint32                        $nbits # unsigned int
                      ,int32                         $level # gcry_random_level
                       ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1500
#/* Create an unpredicable nonce of LENGTH bytes in BUFFER. */
#void gcry_create_nonce (void *buffer, size_t length);
sub gcry_create_nonce(Pointer                       $buffer # void*
                     ,size_t                        $length # Typedef<size_t>->|long unsigned int|
                      ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1544
#/* Generate a new prime number of PRIME_BITS bits and store it in
#   PRIME.  If FACTOR_BITS is non-zero, one of the prime factors of
#   (prime - 1) / 2 must be FACTOR_BITS bits long.  If FACTORS is
#   non-zero, allocate a new, NULL-terminated array holding the prime
#   factors and store it in FACTORS.  FLAGS might be used to influence
#   the prime number generation process.  */
#gcry_error_t gcry_prime_generate (gcry_mpi_t *prime,
#                                  unsigned int prime_bits,
#                                  unsigned int factor_bits,
#                                  gcry_mpi_t **factors,
#                                  gcry_prime_check_func_t cb_func,
#                                  void *cb_arg,
#                                  gcry_random_level_t random_level,
#                                  unsigned int flags);
sub gcry_prime_generate(Pointer[gcry_mpi]             $prime # Typedef<gcry_mpi_t>->|gcry_mpi*|*
                       ,uint32                        $prime_bits # unsigned int
                       ,uint32                        $factor_bits # unsigned int
                       ,Pointer[Pointer[gcry_mpi]]    $factors # Typedef<gcry_mpi_t>->|gcry_mpi*|**
                       ,&cb_func (Pointer, int32, gcry_mpi --> int32) # Typedef<gcry_prime_check_func_t>->|F:int ( void*, int, Typedef<gcry_mpi_t>->|gcry_mpi*|)*|
                       ,Pointer                       $cb_arg # void*
                       ,int32                         $random_level # Typedef<gcry_random_level_t>->|gcry_random_level|
                       ,uint32                        $flags # unsigned int
                        ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1553
#/* Find a generator for PRIME where the factorization of (prime-1) is
#   in the NULL terminated array FACTORS. Return the generator as a
#   newly allocated MPI in R_G.  If START_G is not NULL, use this as
#   teh start for the search. */
#gcry_error_t gcry_prime_group_generator (gcry_mpi_t *r_g,
#                                         gcry_mpi_t prime,
#                                         gcry_mpi_t *factors,
#                                         gcry_mpi_t start_g);
sub gcry_prime_group_generator(Pointer[gcry_mpi]             $r_g # Typedef<gcry_mpi_t>->|gcry_mpi*|*
                              ,gcry_mpi                      $prime # Typedef<gcry_mpi_t>->|gcry_mpi*|
                              ,Pointer[gcry_mpi]             $factors # Typedef<gcry_mpi_t>->|gcry_mpi*|*
                              ,gcry_mpi                      $start_g # Typedef<gcry_mpi_t>->|gcry_mpi*|
                               ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1557
#/* Convenience function to release the FACTORS array. */
#void gcry_prime_release_factors (gcry_mpi_t *factors);
sub gcry_prime_release_factors(Pointer[gcry_mpi] $factors # Typedef<gcry_mpi_t>->|gcry_mpi*|*
                               ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1561
#/* Check wether the number X is prime.  */
#gcry_error_t gcry_prime_check (gcry_mpi_t x, unsigned int flags);
sub gcry_prime_check(gcry_mpi                      $x # Typedef<gcry_mpi_t>->|gcry_mpi*|
                    ,uint32                        $flags # unsigned int
                     ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/gcrypt.h:1572
#/* Release the context object CTX.  */
#void gcry_ctx_release (gcry_ctx_t ctx);
sub gcry_ctx_release(gcry_context $ctx # Typedef<gcry_ctx_t>->|gcry_context*|
                     ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1575
#/* Log data using Libgcrypt's own log interface.  */
#void gcry_log_debug (const char *fmt, ...) _GCRY_GCC_ATTR_PRINTF(1,2);
sub gcry_log_debug(Str $fmt # const char*
                   ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1576
#void gcry_log_debughex (const char *text, const void *buffer, size_t length);
sub gcry_log_debughex(Str                           $text # const char*
                     ,Pointer                       $buffer # const void*
                     ,size_t                        $length # Typedef<size_t>->|long unsigned int|
                      ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1577
#void gcry_log_debugmpi (const char *text, gcry_mpi_t mpi);
sub gcry_log_debugmpi(Str                           $text # const char*
                     ,gcry_mpi                      $mpi # Typedef<gcry_mpi_t>->|gcry_mpi*|
                      ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1579
#void gcry_log_debugpnt (const char *text,
#                        gcry_mpi_point_t point, gcry_ctx_t ctx);
sub gcry_log_debugpnt(Str                           $text # const char*
                     ,gcry_mpi_point                $point # Typedef<gcry_mpi_point_t>->|gcry_mpi_point*|
                     ,gcry_context                  $ctx # Typedef<gcry_ctx_t>->|gcry_context*|
                      ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1580
#void gcry_log_debugsxp (const char *text, gcry_sexp_t sexp);
sub gcry_log_debugsxp(Str                           $text # const char*
                     ,gcry_sexp                     $sexp # Typedef<gcry_sexp_t>->|gcry_sexp*|
                      ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1621
#/* Certain operations can provide progress information.  This function
#   is used to register a handler for retrieving these information. */
#void gcry_set_progress_handler (gcry_handler_progress_t cb, void *cb_data);
sub gcry_set_progress_handler(&cb (Pointer, Str, int32, int32, int32) # Typedef<gcry_handler_progress_t>->|F:void ( void*, const char*, int, int, int)*|
                             ,Pointer                       $cb_data # void*
                              ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1630
#/* Register a custom memory allocation functions. */
#void gcry_set_allocation_handler (
#                             gcry_handler_alloc_t func_alloc,
#                             gcry_handler_alloc_t func_alloc_secure,
#                             gcry_handler_secure_check_t func_secure_check,
#                             gcry_handler_realloc_t func_realloc,
#                             gcry_handler_free_t func_free);
sub gcry_set_allocation_handler(&func_alloc (size_t --> Pointer) # Typedef<gcry_handler_alloc_t>->|F:void* ( Typedef<size_t>->|long unsigned int|)*|
                               ,&func_alloc_secure (size_t --> Pointer) # Typedef<gcry_handler_alloc_t>->|F:void* ( Typedef<size_t>->|long unsigned int|)*|
                               ,&func_secure_check (Pointer --> int32) # Typedef<gcry_handler_secure_check_t>->|F:int ( const void*)*|
                               ,&func_realloc (Pointer, size_t --> Pointer) # Typedef<gcry_handler_realloc_t>->|F:void* ( void*, Typedef<size_t>->|long unsigned int|)*|
                               ,&func_free (Pointer) # Typedef<gcry_handler_free_t>->|F:void ( void*)*|
                                ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1634
#/* Register a function used instead of the internal out of memory
#   handler. */
#void gcry_set_outofcore_handler (gcry_handler_no_mem_t h, void *opaque);
sub gcry_set_outofcore_handler(&h (Pointer, size_t, uint32 --> int32) # Typedef<gcry_handler_no_mem_t>->|F:int ( void*, Typedef<size_t>->|long unsigned int|, unsigned int)*|
                              ,Pointer                       $opaque # void*
                               ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1638
#/* Register a function used instead of the internal fatal error
#   handler. */
#void gcry_set_fatalerror_handler (gcry_handler_error_t fnc, void *opaque);
sub gcry_set_fatalerror_handler(&fnc (Pointer, int32, Str) # Typedef<gcry_handler_error_t>->|F:void ( void*, int, const char*)*|
                               ,Pointer                       $opaque # void*
                                ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1642
#/* Register a function used instead of the internal logging
#   facility. */
#void gcry_set_log_handler (gcry_handler_log_t f, void *opaque);
sub gcry_set_log_handler(&f (Pointer, int32, Str, __va_list_tag) # Typedef<gcry_handler_log_t>->|F:void ( void*, int, const char*, __va_list_tag*)*|
                        ,Pointer                       $opaque # void*
                         ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1645
#/* Reserved for future use. */
#void gcry_set_gettext_handler (const char *(*f)(const char*));
sub gcry_set_gettext_handler(&f (Str --> Str) # F:const char* ( const char*)*
                             ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1649
#/* Libgcrypt uses its own memory allocation.  It is important to use
#   gcry_free () to release memory allocated by libgcrypt. */
#void *gcry_malloc (size_t n) _GCRY_GCC_ATTR_MALLOC;
sub gcry_malloc(size_t $n # Typedef<size_t>->|long unsigned int|
                ) is native(LIB) returns Pointer is export { * }

#-From /usr/include/gcrypt.h:1650
#void *gcry_calloc (size_t n, size_t m) _GCRY_GCC_ATTR_MALLOC;
sub gcry_calloc(size_t                        $n # Typedef<size_t>->|long unsigned int|
               ,size_t                        $m # Typedef<size_t>->|long unsigned int|
                ) is native(LIB) returns Pointer is export { * }

#-From /usr/include/gcrypt.h:1651
#void *gcry_malloc_secure (size_t n) _GCRY_GCC_ATTR_MALLOC;
sub gcry_malloc_secure(size_t $n # Typedef<size_t>->|long unsigned int|
                       ) is native(LIB) returns Pointer is export { * }

#-From /usr/include/gcrypt.h:1652
#void *gcry_calloc_secure (size_t n, size_t m) _GCRY_GCC_ATTR_MALLOC;
sub gcry_calloc_secure(size_t                        $n # Typedef<size_t>->|long unsigned int|
                      ,size_t                        $m # Typedef<size_t>->|long unsigned int|
                       ) is native(LIB) returns Pointer is export { * }

#-From /usr/include/gcrypt.h:1653
#void *gcry_realloc (void *a, size_t n);
sub gcry_realloc(Pointer                       $a # void*
                ,size_t                        $n # Typedef<size_t>->|long unsigned int|
                 ) is native(LIB) returns Pointer is export { * }

#-From /usr/include/gcrypt.h:1654
#char *gcry_strdup (const char *string) _GCRY_GCC_ATTR_MALLOC;
sub gcry_strdup(Str $string # const char*
                ) is native(LIB) returns Str is export { * }

#-From /usr/include/gcrypt.h:1655
#void *gcry_xmalloc (size_t n) _GCRY_GCC_ATTR_MALLOC;
sub gcry_xmalloc(size_t $n # Typedef<size_t>->|long unsigned int|
                 ) is native(LIB) returns Pointer is export { * }

#-From /usr/include/gcrypt.h:1656
#void *gcry_xcalloc (size_t n, size_t m) _GCRY_GCC_ATTR_MALLOC;
sub gcry_xcalloc(size_t                        $n # Typedef<size_t>->|long unsigned int|
                ,size_t                        $m # Typedef<size_t>->|long unsigned int|
                 ) is native(LIB) returns Pointer is export { * }

#-From /usr/include/gcrypt.h:1657
#void *gcry_xmalloc_secure (size_t n) _GCRY_GCC_ATTR_MALLOC;
sub gcry_xmalloc_secure(size_t $n # Typedef<size_t>->|long unsigned int|
                        ) is native(LIB) returns Pointer is export { * }

#-From /usr/include/gcrypt.h:1658
#void *gcry_xcalloc_secure (size_t n, size_t m) _GCRY_GCC_ATTR_MALLOC;
sub gcry_xcalloc_secure(size_t                        $n # Typedef<size_t>->|long unsigned int|
                       ,size_t                        $m # Typedef<size_t>->|long unsigned int|
                        ) is native(LIB) returns Pointer is export { * }

#-From /usr/include/gcrypt.h:1659
#void *gcry_xrealloc (void *a, size_t n);
sub gcry_xrealloc(Pointer                       $a # void*
                 ,size_t                        $n # Typedef<size_t>->|long unsigned int|
                  ) is native(LIB) returns Pointer is export { * }

#-From /usr/include/gcrypt.h:1660
#char *gcry_xstrdup (const char * a) _GCRY_GCC_ATTR_MALLOC;
sub gcry_xstrdup(Str $a # const char*
                 ) is native(LIB) returns Str is export { * }

#-From /usr/include/gcrypt.h:1661
#void  gcry_free (void *a);
sub gcry_free(Pointer $a # void*
              ) is native(LIB)  is export { * }

#-From /usr/include/gcrypt.h:1664
#/* Return true if A is allocated in "secure" memory. */
#int gcry_is_secure (const void *a) _GCRY_GCC_ATTR_PURE;
sub gcry_is_secure(Pointer $a # const void*
                   ) is native(LIB) returns int32 is export { * }


# == /usr/include/x86_64-linux-gnu/gpg-error.h ==

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:704
#/* Initialize the library.  This function should be run early.  */
#gpg_error_t gpg_err_init (void) _GPG_ERR_CONSTRUCTOR;
sub gpg_err_init(
                 ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:718
#   required.  */
#void gpg_err_deinit (int mode);
sub gpg_err_deinit(int32 $mode # int
                   ) is native(LIB)  is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:721
#/* Register blocking system I/O clamping functions.  */
#void gpgrt_set_syscall_clamp (void (*pre)(void), void (*post)(void));
sub gpgrt_set_syscall_clamp(&pre () # F:void ( )*
                           ,&post () # F:void ( )*
                            ) is native(LIB)  is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:724
#/* Register a custom malloc/realloc/free function.  */
#void gpgrt_set_alloc_func  (void *(*f)(void *a, size_t n));
sub gpgrt_set_alloc_func(&f (Pointer, size_t --> Pointer) # F:void* ( void*, Typedef<size_t>->|long unsigned int|)*
                         ) is native(LIB)  is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:733
#/* Construct an error value from an error code and source.  Within a
#   subsystem, use gpg_error.  */
#static GPG_ERR_INLINE gpg_error_t
#gpg_err_make (gpg_err_source_t source, gpg_err_code_t code)
sub gpg_err_make(int32                         $source # gpg_err_source_t
                ,int32                         $code # gpg_err_code_t
                 ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:748
#static GPG_ERR_INLINE gpg_error_t
#gpg_error (gpg_err_code_t code)
sub gpg_error(int32 $code # gpg_err_code_t
              ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:756
#/* Retrieve the error code from an error value.  */
#static GPG_ERR_INLINE gpg_err_code_t
#gpg_err_code (gpg_error_t err)
sub gpg_err_code(gpg_error_t $err # Typedef<gpg_error_t>->|unsigned int|
                 ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:764
#/* Retrieve the error source from an error value.  */
#static GPG_ERR_INLINE gpg_err_source_t
#gpg_err_source (gpg_error_t err)
sub gpg_err_source(gpg_error_t $err # Typedef<gpg_error_t>->|unsigned int|
                   ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:775
#/* Return a pointer to a string containing a description of the error
#   code in the error value ERR.  This function is not thread-safe.  */
#const char *gpg_strerror (gpg_error_t err);
sub gpg_strerror(gpg_error_t $err # Typedef<gpg_error_t>->|unsigned int|
                 ) is native(LIB) returns Str is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:784
#/* Return the error string for ERR in the user-supplied buffer BUF of
#   size BUFLEN.  This function is, in contrast to gpg_strerror,
#   thread-safe if a thread-safe strerror_r() function is provided by
#   the system.  If the function succeeds, 0 is returned and BUF
#   contains the string describing the error.  If the buffer was not
#   large enough, ERANGE is returned and BUF contains as much of the
#   beginning of the error string as fits into the buffer.  */
#int gpg_strerror_r (gpg_error_t err, char *buf, size_t buflen);
sub gpg_strerror_r(gpg_error_t                   $err # Typedef<gpg_error_t>->|unsigned int|
                  ,Str                           $buf # char*
                  ,size_t                        $buflen # Typedef<size_t>->|long unsigned int|
                   ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:788
#/* Return a pointer to a string containing a description of the error
#   source in the error value ERR.  */
#const char *gpg_strsource (gpg_error_t err);
sub gpg_strsource(gpg_error_t $err # Typedef<gpg_error_t>->|unsigned int|
                  ) is native(LIB) returns Str is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:796
#/* Retrieve the error code for the system error ERR.  This returns
#   GPG_ERR_UNKNOWN_ERRNO if the system error is not mapped (report
#   this). */
#gpg_err_code_t gpg_err_code_from_errno (int err);
sub gpg_err_code_from_errno(int32 $err # int
                            ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:801
#/* Retrieve the system error for the error code CODE.  This returns 0
#   if CODE is not a system error code.  */
#int gpg_err_code_to_errno (gpg_err_code_t code);
sub gpg_err_code_to_errno(int32 $code # gpg_err_code_t
                          ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:807
#/* Retrieve the error code directly from the ERRNO variable.  This
#   returns GPG_ERR_UNKNOWN_ERRNO if the system error is not mapped
#   (report this) and GPG_ERR_MISSING_ERRNO if ERRNO has the value 0. */
#gpg_err_code_t gpg_err_code_from_syserror (void);
sub gpg_err_code_from_syserror(
                               ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:812
#/* Set the ERRNO variable.  This function is the preferred way to set
#   ERRNO due to peculiarities on WindowsCE.  */
#void gpg_err_set_errno (int err);
sub gpg_err_set_errno(int32 $err # int
                      ) is native(LIB)  is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:815
#/* Return or check the version.  Both functions are identical.  */
#const char *gpgrt_check_version (const char *req_version);
sub gpgrt_check_version(Str $req_version # const char*
                        ) is native(LIB) returns Str is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:816
#const char *gpg_error_check_version (const char *req_version);
sub gpg_error_check_version(Str $req_version # const char*
                            ) is native(LIB) returns Str is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:836
#static GPG_ERR_INLINE gpg_error_t
#gpg_err_make_from_errno (gpg_err_source_t source, int err)
sub gpg_err_make_from_errno(int32                         $source # gpg_err_source_t
                           ,int32                         $err # int
                            ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:843
#static GPG_ERR_INLINE gpg_error_t
#gpg_error_from_errno (int err)
sub gpg_error_from_errno(int32 $err # int
                         ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:849
#static GPG_ERR_INLINE gpg_error_t
#gpg_error_from_syserror (void)
sub gpg_error_from_syserror(
                            ) is native(LIB) returns gpg_error_t is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:881
#/* NB: If GPGRT_LOCK_DEFINE is not used, zero out the lock variable
#   before passing it to gpgrt_lock_init.  */
#gpg_err_code_t gpgrt_lock_init (gpgrt_lock_t *lockhd);
sub gpgrt_lock_init(gpgrt_lock_t $lockhd # gpgrt_lock_t*
                    ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:882
#gpg_err_code_t gpgrt_lock_lock (gpgrt_lock_t *lockhd);
sub gpgrt_lock_lock(gpgrt_lock_t $lockhd # gpgrt_lock_t*
                    ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:883
#gpg_err_code_t gpgrt_lock_trylock (gpgrt_lock_t *lockhd);
sub gpgrt_lock_trylock(gpgrt_lock_t $lockhd # gpgrt_lock_t*
                       ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:884
#gpg_err_code_t gpgrt_lock_unlock (gpgrt_lock_t *lockhd);
sub gpgrt_lock_unlock(gpgrt_lock_t $lockhd # gpgrt_lock_t*
                      ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:885
#gpg_err_code_t gpgrt_lock_destroy (gpgrt_lock_t *lockhd);
sub gpgrt_lock_destroy(gpgrt_lock_t $lockhd # gpgrt_lock_t*
                       ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:891
#gpg_err_code_t gpgrt_yield (void);
sub gpgrt_yield(
                ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1001
#gpgrt_stream_t gpgrt_fopen (const char *_GPGRT__RESTRICT path,
#                            const char *_GPGRT__RESTRICT mode);
sub gpgrt_fopen(Str                           $path # const const char*
               ,Str                           $mode # const const char*
                ) is native(LIB) returns _gpgrt__stream is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1007
#gpgrt_stream_t gpgrt_mopen (void *_GPGRT__RESTRICT data,
#                            size_t data_n, size_t data_len,
#                            unsigned int grow,
#                            void *(*func_realloc) (void *mem, size_t size),
#                            void (*func_free) (void *mem),
#                            const char *_GPGRT__RESTRICT mode);
sub gpgrt_mopen(Pointer                       $data # const void*
               ,size_t                        $data_n # Typedef<size_t>->|long unsigned int|
               ,size_t                        $data_len # Typedef<size_t>->|long unsigned int|
               ,uint32                        $grow # unsigned int
               ,&func_realloc (Pointer, size_t --> Pointer) # F:void* ( void*, Typedef<size_t>->|long unsigned int|)*
               ,&func_free (Pointer) # F:void ( void*)*
               ,Str                           $mode # const const char*
                ) is native(LIB) returns _gpgrt__stream is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1009
#gpgrt_stream_t gpgrt_fopenmem (size_t memlimit,
#                               const char *_GPGRT__RESTRICT mode);
sub gpgrt_fopenmem(size_t                        $memlimit # Typedef<size_t>->|long unsigned int|
                  ,Str                           $mode # const const char*
                   ) is native(LIB) returns _gpgrt__stream is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1012
#gpgrt_stream_t gpgrt_fopenmem_init (size_t memlimit,
#                                    const char *_GPGRT__RESTRICT mode,
#                                    const void *data, size_t datalen);
sub gpgrt_fopenmem_init(size_t                        $memlimit # Typedef<size_t>->|long unsigned int|
                       ,Str                           $mode # const const char*
                       ,Pointer                       $data # const void*
                       ,size_t                        $datalen # Typedef<size_t>->|long unsigned int|
                        ) is native(LIB) returns _gpgrt__stream is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1013
#gpgrt_stream_t gpgrt_fdopen    (int filedes, const char *mode);
sub gpgrt_fdopen(int32                         $filedes # int
                ,Str                           $mode # const char*
                 ) is native(LIB) returns _gpgrt__stream is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1014
#gpgrt_stream_t gpgrt_fdopen_nc (int filedes, const char *mode);
sub gpgrt_fdopen_nc(int32                         $filedes # int
                   ,Str                           $mode # const char*
                    ) is native(LIB) returns _gpgrt__stream is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1015
#gpgrt_stream_t gpgrt_sysopen    (gpgrt_syshd_t *syshd, const char *mode);
sub gpgrt_sysopen(_gpgrt_syshd                  $syshd # Typedef<gpgrt_syshd_t>->|_gpgrt_syshd|*
                 ,Str                           $mode # const char*
                  ) is native(LIB) returns _gpgrt__stream is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1016
#gpgrt_stream_t gpgrt_sysopen_nc (gpgrt_syshd_t *syshd, const char *mode);
sub gpgrt_sysopen_nc(_gpgrt_syshd                  $syshd # Typedef<gpgrt_syshd_t>->|_gpgrt_syshd|*
                    ,Str                           $mode # const char*
                     ) is native(LIB) returns _gpgrt__stream is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1017
#gpgrt_stream_t gpgrt_fpopen    (FILE *fp, const char *mode);
sub gpgrt_fpopen(_IO_FILE                      $fp # Typedef<FILE>->|_IO_FILE|*
                ,Str                           $mode # const char*
                 ) is native(LIB) returns _gpgrt__stream is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1018
#gpgrt_stream_t gpgrt_fpopen_nc (FILE *fp, const char *mode);
sub gpgrt_fpopen_nc(_IO_FILE                      $fp # Typedef<FILE>->|_IO_FILE|*
                   ,Str                           $mode # const char*
                    ) is native(LIB) returns _gpgrt__stream is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1021
#gpgrt_stream_t gpgrt_freopen (const char *_GPGRT__RESTRICT path,
#                              const char *_GPGRT__RESTRICT mode,
#                              gpgrt_stream_t _GPGRT__RESTRICT stream);
sub gpgrt_freopen(Str                           $path # const const char*
                 ,Str                           $mode # const const char*
                 ,_gpgrt__stream                $stream # const Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                  ) is native(LIB) returns _gpgrt__stream is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1024
#gpgrt_stream_t gpgrt_fopencookie (void *_GPGRT__RESTRICT cookie,
#                                  const char *_GPGRT__RESTRICT mode,
#                                  gpgrt_cookie_io_functions_t functions);
sub gpgrt_fopencookie(Pointer                       $cookie # const void*
                     ,Str                           $mode # const const char*
                     ,_gpgrt_cookie_io_functions    $functions # Typedef<gpgrt_cookie_io_functions_t>->|_gpgrt_cookie_io_functions|
                      ) is native(LIB) returns _gpgrt__stream is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1025
#int gpgrt_fclose (gpgrt_stream_t stream);
sub gpgrt_fclose(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                 ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1027
#int gpgrt_fclose_snatch (gpgrt_stream_t stream,
#                         void **r_buffer, size_t *r_buflen);
sub gpgrt_fclose_snatch(_gpgrt__stream                $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                       ,Pointer[Pointer]              $r_buffer # void**
                       ,Pointer[size_t]               $r_buflen # Typedef<size_t>->|long unsigned int|*
                        ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1029
#int gpgrt_onclose (gpgrt_stream_t stream, int mode,
#                   void (*fnc) (gpgrt_stream_t, void*), void *fnc_value);
sub gpgrt_onclose(_gpgrt__stream                $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                 ,int32                         $mode # int
                 ,&fnc (_gpgrt__stream, Pointer) # F:void ( Typedef<gpgrt_stream_t>->|_gpgrt__stream*|, void*)*
                 ,Pointer                       $fnc_value # void*
                  ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1030
#int gpgrt_fileno (gpgrt_stream_t stream);
sub gpgrt_fileno(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                 ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1031
#int gpgrt_fileno_unlocked (gpgrt_stream_t stream);
sub gpgrt_fileno_unlocked(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                          ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1032
#int gpgrt_syshd (gpgrt_stream_t stream, gpgrt_syshd_t *syshd);
sub gpgrt_syshd(_gpgrt__stream                $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
               ,_gpgrt_syshd                  $syshd # Typedef<gpgrt_syshd_t>->|_gpgrt_syshd|*
                ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1033
#int gpgrt_syshd_unlocked (gpgrt_stream_t stream, gpgrt_syshd_t *syshd);
sub gpgrt_syshd_unlocked(_gpgrt__stream                $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                        ,_gpgrt_syshd                  $syshd # Typedef<gpgrt_syshd_t>->|_gpgrt_syshd|*
                         ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1035
#void _gpgrt_set_std_fd (int no, int fd);
sub _gpgrt_set_std_fd(int32                         $no # int
                     ,int32                         $fd # int
                      ) is native(LIB)  is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1036
#gpgrt_stream_t _gpgrt_get_std_stream (int fd);
sub _gpgrt_get_std_stream(int32 $fd # int
                          ) is native(LIB) returns _gpgrt__stream is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1043
#void gpgrt_flockfile (gpgrt_stream_t stream);
sub gpgrt_flockfile(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                    ) is native(LIB)  is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1044
#int  gpgrt_ftrylockfile (gpgrt_stream_t stream);
sub gpgrt_ftrylockfile(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                       ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1045
#void gpgrt_funlockfile (gpgrt_stream_t stream);
sub gpgrt_funlockfile(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                      ) is native(LIB)  is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1047
#int gpgrt_feof (gpgrt_stream_t stream);
sub gpgrt_feof(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
               ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1048
#int gpgrt_feof_unlocked (gpgrt_stream_t stream);
sub gpgrt_feof_unlocked(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                        ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1049
#int gpgrt_ferror (gpgrt_stream_t stream);
sub gpgrt_ferror(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                 ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1050
#int gpgrt_ferror_unlocked (gpgrt_stream_t stream);
sub gpgrt_ferror_unlocked(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                          ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1051
#void gpgrt_clearerr (gpgrt_stream_t stream);
sub gpgrt_clearerr(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                   ) is native(LIB)  is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1052
#void gpgrt_clearerr_unlocked (gpgrt_stream_t stream);
sub gpgrt_clearerr_unlocked(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                            ) is native(LIB)  is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1054
#int _gpgrt_pending (gpgrt_stream_t stream);          /* (private) */
sub _gpgrt_pending(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                   ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1055
#int _gpgrt_pending_unlocked (gpgrt_stream_t stream); /* (private) */
sub _gpgrt_pending_unlocked(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                            ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1065
#int gpgrt_fflush (gpgrt_stream_t stream);
sub gpgrt_fflush(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                 ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1066
#int gpgrt_fseek (gpgrt_stream_t stream, long int offset, int whence);
sub gpgrt_fseek(_gpgrt__stream                $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
               ,long                          $offset # long int
               ,int32                         $whence # int
                ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1067
#int gpgrt_fseeko (gpgrt_stream_t stream, gpgrt_off_t offset, int whence);
sub gpgrt_fseeko(_gpgrt__stream                $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                ,gpgrt_off_t                   $offset # Typedef<gpgrt_off_t>->|long int|
                ,int32                         $whence # int
                 ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1068
#long int gpgrt_ftell (gpgrt_stream_t stream);
sub gpgrt_ftell(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                ) is native(LIB) returns long is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1069
#gpgrt_off_t gpgrt_ftello (gpgrt_stream_t stream);
sub gpgrt_ftello(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                 ) is native(LIB) returns gpgrt_off_t is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1070
#void gpgrt_rewind (gpgrt_stream_t stream);
sub gpgrt_rewind(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                 ) is native(LIB)  is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1072
#int gpgrt_fgetc (gpgrt_stream_t stream);
sub gpgrt_fgetc(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1073
#int gpgrt_fputc (int c, gpgrt_stream_t stream);
sub gpgrt_fputc(int32                         $c # int
               ,_gpgrt__stream                $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1075
#int _gpgrt_getc_underflow (gpgrt_stream_t stream);       /* (private) */
sub _gpgrt_getc_underflow(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                          ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1076
#int _gpgrt_putc_overflow (int c, gpgrt_stream_t stream); /* (private) */
sub _gpgrt_putc_overflow(int32                         $c # int
                        ,_gpgrt__stream                $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                         ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1095
#int gpgrt_ungetc (int c, gpgrt_stream_t stream);
sub gpgrt_ungetc(int32                         $c # int
                ,_gpgrt__stream                $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                 ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1099
#int gpgrt_read (gpgrt_stream_t _GPGRT__RESTRICT stream,
#                void *_GPGRT__RESTRICT buffer, size_t bytes_to_read,
#                size_t *_GPGRT__RESTRICT bytes_read);
sub gpgrt_read(_gpgrt__stream                $stream # const Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
              ,Pointer                       $buffer # const void*
              ,size_t                        $bytes_to_read # Typedef<size_t>->|long unsigned int|
              ,Pointer[size_t]               $bytes_read # const Typedef<size_t>->|long unsigned int|*
               ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1102
#int gpgrt_write (gpgrt_stream_t _GPGRT__RESTRICT stream,
#                 const void *_GPGRT__RESTRICT buffer, size_t bytes_to_write,
#                 size_t *_GPGRT__RESTRICT bytes_written);
sub gpgrt_write(_gpgrt__stream                $stream # const Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
               ,Pointer                       $buffer # const const void*
               ,size_t                        $bytes_to_write # Typedef<size_t>->|long unsigned int|
               ,Pointer[size_t]               $bytes_written # const Typedef<size_t>->|long unsigned int|*
                ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1106
#int gpgrt_write_sanitized (gpgrt_stream_t _GPGRT__RESTRICT stream,
#                           const void *_GPGRT__RESTRICT buffer, size_t length,
#                           const char *delimiters,
#                           size_t *_GPGRT__RESTRICT bytes_written);
sub gpgrt_write_sanitized(_gpgrt__stream                $stream # const Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                         ,Pointer                       $buffer # const const void*
                         ,size_t                        $length # Typedef<size_t>->|long unsigned int|
                         ,Str                           $delimiters # const char*
                         ,Pointer[size_t]               $bytes_written # const Typedef<size_t>->|long unsigned int|*
                          ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1110
#int gpgrt_write_hexstring (gpgrt_stream_t _GPGRT__RESTRICT stream,
#                           const void *_GPGRT__RESTRICT buffer, size_t length,
#                           int reserved,
#                           size_t *_GPGRT__RESTRICT bytes_written);
sub gpgrt_write_hexstring(_gpgrt__stream                $stream # const Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                         ,Pointer                       $buffer # const const void*
                         ,size_t                        $length # Typedef<size_t>->|long unsigned int|
                         ,int32                         $reserved # int
                         ,Pointer[size_t]               $bytes_written # const Typedef<size_t>->|long unsigned int|*
                          ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1113
#size_t gpgrt_fread (void *_GPGRT__RESTRICT ptr, size_t size, size_t nitems,
#                    gpgrt_stream_t _GPGRT__RESTRICT stream);
sub gpgrt_fread(Pointer                       $ptr # const void*
               ,size_t                        $size # Typedef<size_t>->|long unsigned int|
               ,size_t                        $nitems # Typedef<size_t>->|long unsigned int|
               ,_gpgrt__stream                $stream # const Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                ) is native(LIB) returns size_t is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1115
#size_t gpgrt_fwrite (const void *_GPGRT__RESTRICT ptr, size_t size, size_t memb,
#                     gpgrt_stream_t _GPGRT__RESTRICT stream);
sub gpgrt_fwrite(Pointer                       $ptr # const const void*
                ,size_t                        $size # Typedef<size_t>->|long unsigned int|
                ,size_t                        $memb # Typedef<size_t>->|long unsigned int|
                ,_gpgrt__stream                $stream # const Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                 ) is native(LIB) returns size_t is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1118
#char *gpgrt_fgets (char *_GPGRT__RESTRICT s, int n,
#                   gpgrt_stream_t _GPGRT__RESTRICT stream);
sub gpgrt_fgets(Str                           $s # const char*
               ,int32                         $n # int
               ,_gpgrt__stream                $stream # const Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                ) is native(LIB) returns Str is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1120
#int gpgrt_fputs (const char *_GPGRT__RESTRICT s,
#                 gpgrt_stream_t _GPGRT__RESTRICT stream);
sub gpgrt_fputs(Str                           $s # const const char*
               ,_gpgrt__stream                $stream # const Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1122
#int gpgrt_fputs_unlocked (const char *_GPGRT__RESTRICT s,
#                          gpgrt_stream_t _GPGRT__RESTRICT stream);
sub gpgrt_fputs_unlocked(Str                           $s # const const char*
                        ,_gpgrt__stream                $stream # const Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                         ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1126
#ssize_t gpgrt_getline (char *_GPGRT__RESTRICT *_GPGRT__RESTRICT lineptr,
#                       size_t *_GPGRT__RESTRICT n,
#                       gpgrt_stream_t stream);
sub gpgrt_getline(Pointer[Str]                  $lineptr # const const char**
                 ,Pointer[size_t]               $n # const Typedef<size_t>->|long unsigned int|*
                 ,_gpgrt__stream                $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                  ) is native(LIB) returns __ssize_t is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1129
#ssize_t gpgrt_read_line (gpgrt_stream_t stream,
#                         char **addr_of_buffer, size_t *length_of_buffer,
#                         size_t *max_length);
sub gpgrt_read_line(_gpgrt__stream                $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                   ,Pointer[Str]                  $addr_of_buffer # char**
                   ,Pointer[size_t]               $length_of_buffer # Typedef<size_t>->|long unsigned int|*
                   ,Pointer[size_t]               $max_length # Typedef<size_t>->|long unsigned int|*
                    ) is native(LIB) returns __ssize_t is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1130
#void gpgrt_free (void *a);
sub gpgrt_free(Pointer $a # void*
               ) is native(LIB)  is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1134
#int gpgrt_fprintf (gpgrt_stream_t _GPGRT__RESTRICT stream,
#                   const char *_GPGRT__RESTRICT format, ...)
#                   _GPGRT_GCC_A_PRINTF(2,3);
sub gpgrt_fprintf(_gpgrt__stream                $stream # const Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                 ,Str                           $format # const const char*
                  ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1137
#int gpgrt_fprintf_unlocked (gpgrt_stream_t _GPGRT__RESTRICT stream,
#                            const char *_GPGRT__RESTRICT format, ...)
#                            _GPGRT_GCC_A_PRINTF(2,3);
sub gpgrt_fprintf_unlocked(_gpgrt__stream                $stream # const Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                          ,Str                           $format # const const char*
                           ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1140
#int gpgrt_printf (const char *_GPGRT__RESTRICT format, ...)
#                  _GPGRT_GCC_A_PRINTF(1,2);
sub gpgrt_printf(Str $format # const const char*
                 ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1142
#int gpgrt_printf_unlocked (const char *_GPGRT__RESTRICT format, ...)
#                           _GPGRT_GCC_A_PRINTF(1,2);
sub gpgrt_printf_unlocked(Str $format # const const char*
                          ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1146
#int gpgrt_vfprintf (gpgrt_stream_t _GPGRT__RESTRICT stream,
#                    const char *_GPGRT__RESTRICT format, va_list ap)
#                    _GPGRT_GCC_A_PRINTF(2,0);
sub gpgrt_vfprintf(_gpgrt__stream                $stream # const Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                  ,Str                           $format # const const char*
                  ,__va_list_tag                 $ap # __va_list_tag*
                   ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1149
#int gpgrt_vfprintf_unlocked (gpgrt_stream_t _GPGRT__RESTRICT stream,
#                             const char *_GPGRT__RESTRICT format, va_list ap)
#                             _GPGRT_GCC_A_PRINTF(2,0);
sub gpgrt_vfprintf_unlocked(_gpgrt__stream                $stream # const Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                           ,Str                           $format # const const char*
                           ,__va_list_tag                 $ap # __va_list_tag*
                            ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1152
#int gpgrt_setvbuf (gpgrt_stream_t _GPGRT__RESTRICT stream,
#                   char *_GPGRT__RESTRICT buf, int mode, size_t size);
sub gpgrt_setvbuf(_gpgrt__stream                $stream # const Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                 ,Str                           $buf # const char*
                 ,int32                         $mode # int
                 ,size_t                        $size # Typedef<size_t>->|long unsigned int|
                  ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1154
#void gpgrt_setbuf (gpgrt_stream_t _GPGRT__RESTRICT stream,
#                   char *_GPGRT__RESTRICT buf);
sub gpgrt_setbuf(_gpgrt__stream                $stream # const Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                ,Str                           $buf # const char*
                 ) is native(LIB)  is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1156
#void gpgrt_set_binary (gpgrt_stream_t stream);
sub gpgrt_set_binary(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                     ) is native(LIB)  is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1158
#gpgrt_stream_t gpgrt_tmpfile (void);
sub gpgrt_tmpfile(
                  ) is native(LIB) returns _gpgrt__stream is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1161
#void gpgrt_opaque_set (gpgrt_stream_t _GPGRT__RESTRICT stream,
#                       void *_GPGRT__RESTRICT opaque);
sub gpgrt_opaque_set(_gpgrt__stream                $stream # const Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                    ,Pointer                       $opaque # const void*
                     ) is native(LIB)  is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1162
#void *gpgrt_opaque_get (gpgrt_stream_t stream);
sub gpgrt_opaque_get(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                     ) is native(LIB) returns Pointer is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1164
#void gpgrt_fname_set (gpgrt_stream_t stream, const char *fname);
sub gpgrt_fname_set(_gpgrt__stream                $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                   ,Str                           $fname # const char*
                    ) is native(LIB)  is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1165
#const char *gpgrt_fname_get (gpgrt_stream_t stream);
sub gpgrt_fname_get(_gpgrt__stream $stream # Typedef<gpgrt_stream_t>->|_gpgrt__stream*|
                    ) is native(LIB) returns Str is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1168
#int gpgrt_asprintf (char **r_buf, const char * _GPGRT__RESTRICT format, ...)
#                    _GPGRT_GCC_A_PRINTF(2,3);
sub gpgrt_asprintf(Pointer[Str]                  $r_buf # char**
                  ,Str                           $format # const const char*
                   ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1171
#int gpgrt_vasprintf (char **r_buf, const char * _GPGRT__RESTRICT format,
#                     va_list ap)
#                     _GPGRT_GCC_A_PRINTF(2,0);
sub gpgrt_vasprintf(Pointer[Str]                  $r_buf # char**
                   ,Str                           $format # const const char*
                   ,__va_list_tag                 $ap # __va_list_tag*
                    ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1173
#char *gpgrt_bsprintf (const char * _GPGRT__RESTRICT format, ...)
#                      _GPGRT_GCC_A_PRINTF(1,2);
sub gpgrt_bsprintf(Str $format # const const char*
                   ) is native(LIB) returns Str is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1175
#char *gpgrt_vbsprintf (const char * _GPGRT__RESTRICT format, va_list ap)
#                       _GPGRT_GCC_A_PRINTF(1,0);
sub gpgrt_vbsprintf(Str                           $format # const const char*
                   ,__va_list_tag                 $ap # __va_list_tag*
                    ) is native(LIB) returns Str is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1178
#int gpgrt_snprintf (char *buf, size_t bufsize,
#                    const char * _GPGRT__RESTRICT format, ...)
#                    _GPGRT_GCC_A_PRINTF(3,4);
sub gpgrt_snprintf(Str                           $buf # char*
                  ,size_t                        $bufsize # Typedef<size_t>->|long unsigned int|
                  ,Str                           $format # const const char*
                   ) is native(LIB) returns int32 is export { * }

#-From /usr/include/x86_64-linux-gnu/gpg-error.h:1181
#int gpgrt_vsnprintf (char *buf,size_t bufsize,
#                     const char * _GPGRT__RESTRICT format, va_list arg_ptr)
#                     _GPGRT_GCC_A_PRINTF(3,0);
sub gpgrt_vsnprintf(Str                           $buf # char*
                   ,size_t                        $bufsize # Typedef<size_t>->|long unsigned int|
                   ,Str                           $format # const const char*
                   ,__va_list_tag                 $arg_ptr # __va_list_tag*
                    ) is native(LIB) returns int32 is export { * }


# == /usr/include/alloca.h ==

#-From /usr/include/alloca.h:32
#/* Allocate a block that will be freed when the calling function exits.  */
#extern void *alloca (size_t __size) __THROW;
sub alloca(size_t $__size # Typedef<size_t>->|long unsigned int|
           ) is native(LIB) returns Pointer is export { * }

## Externs

