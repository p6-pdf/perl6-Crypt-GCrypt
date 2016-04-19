use v6;

class X::Crypt::GCrypt::Error is Exception {
    has Str  $.message is required;
    has UInt $.domain;
    has UInt $.status;
    method message {"GCrypt error: {$.message}"}
}
use v6;

class Crypt::GCrypt {
    use Crypt::GCrypt::Raw;
    use NativeCall;

    our $Sec-Mem-Size = 2 ** 15;

    has int $!type;
    my subset Action of Str where 'encrypting' | 'decrypting';
    has Action $!action;
    has gcry_cipher_hd_t $!h;
    has gcry_md_hd_t $!h-md;
    has gcry_error_t $!err;
    has gcry_int $!mode;
    has CArray $buffer;
    has size_t $.blklen;
    has size_t $.keylen;
    has Bool $need-to-call-finish;

    method !map-cipher-mode(Str $mode --> gcry_cipher_modes ) {
	constant %modes = %(
	    :ecb(GCRY_CIPHER_MODE_ECB),
	    :cfb(GCRY_CIPHER_MODE_CFB),
	    :cbc(GCRY_CIPHER_MODE_CBC),
	    :ofb(GCRY_CIPHER_MODE_OFB),
	    :stream(GCRY_CIPHER_MODE_STREAM),
	);

	with %modes{$mode} {
            return $_
        }
	else {
	    die "unknown cipher mode $mode"
	}
    }

    method !init-library {
	constant MIN_GCRYPT_VERSION = '1.6.0';

	my $gcrypt-version = gcry_check_version();
	die "libgcrypt version mismatch (need: >= {MIN_GCRYPT_VERSION}, got $gcrypt-version)"
	    unless $gcrypt-version ge MIN_GCRYPT_VERSION;
	my gcry_ctl_cmd $cmd;
	unless (gcry_control($cmd = GCRYCTL_INITIALIZATION_FINISHED_P)) {
	    #`{{ we just need to make sure that the right version is available
	         Why do it this way?  see 
                 /usr/share/doc/libgcrypt11-doc/html/Initializing-the-library.html#sample-use-suspend-secmem

                 We don't want to see any warnings, e.g. because we have not yet
                 parsed program options which might be used to suppress such
                 warnings.
            }}
            gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
     
            #`{{ Allocate a pool of 32k secure memory.  This make the secure memory
                 available and also drops privileges where needed.  

                 This mirrors changes made in libgcrypt 1.4.3, to auto-initialize
                 the library with 32KB of secure memory if no other initialization
                 has been done.

            }}
            gcry_control2(GCRYCTL_INIT_SECMEM, $Sec-Mem-Size, 0);
     
            #`{{ It is now okay to let Libgcrypt complain when there was/is
                 a problem with the secure memory.
            }}
            gcry_control(GCRYCTL_RESUME_SECMEM_WARN);

            gcry_control(GCRYCTL_INITIALIZATION_FINISHED);

	}
    }

    our sub cipher_algo_available(Str $name --> Bool) {
	? gcry_cipher_map_name($name.lc)
    }

    our sub digest_algo_available(Str $name --> Bool) {
	? gcry_md_map_name($name.lc)
    }

    submethod BUILD(Str :$type!,
		    Str :$algorithm!,
		    |c) {
	self.build-gcrypt( $type.lc, $algorithm.lc, |c);
    }

    multi submethod build-gcrypt(
	'cipher',
	Str $algorithm,
	Str :$mode is copy,
	Bool :$secure,
	Bool :$enable-sync,
    ) {
	my gcry_uint $flags = 0;
	$flags +|= GCRY_CIPHER_SECURE if $secure;
	$flags +|= GCRY_CIPHER_ENABLE_SYNC if $enable-sync;

	self!init-library();

	my gcry_int $algo = gcry_cipher_map_name($algorithm.lc);
	die "Unknown cipher algorithm $algorithm"
	    unless $algo;
	$!blklen = gcry_cipher_get_algo_blklen($algo);
	$!keylen = gcry_cipher_get_algo_blklen($algo);
	$mode //= $!blklen > 1 ?? 'cbc' !! 'stream';
	$!mode = self!map-cipher-mode($mode);
	$!err //= gcry_cipher_open($!h, $algo, $!mode, $flags);
    }

    multi method start(Action $!action) {
	$!buffer = CArray[uint8].new;
	$!buffer[$!blklen - 1] = 0;
	$!need-to-call-finish = True;    
    }
    
    method set-key($key) {
	...
    }
    method set-iv($vect) {
	...
    }

}


