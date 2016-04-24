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

    has Str $.type where 'cipher'; #|todo: asymm digest
    my subset Action of Str where 'encrypting' | 'decrypting';
    has Action $!action;
    has gcry_cipher_hd_t $!h;
    has gcry_error_t $!err;
    has gcry_int $!mode;
    has CArray $buffer;
    has size_t $.blklen;
    has size_t $.keylen;
    has Bool $need-to-call-finish;

    our constant %CIPHER-MODE = %(
	:ecb(GCRY_CIPHER_MODE_ECB),
	:cfb(GCRY_CIPHER_MODE_CFB),
	:cbc(GCRY_CIPHER_MODE_CBC),
	:ofb(GCRY_CIPHER_MODE_OFB),
	:stream(GCRY_CIPHER_MODE_STREAM),
    );
    subset ModeName of Str where %CIPHER-MODE{$_}:exists;

    method !map-cipher-mode(ModeName $mode --> gcry_cipher_modes ) {
	%CIPHER-MODE{$mode}
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
    subset CipherName of Str where { gcry_cipher_map_name($_) }

    our sub digest_algo_available(Str $name --> Bool) {
	? gcry_md_map_name($name.lc)
    }
    subset DigestName of Str where { gcry_md_map_name($_) }

    submethod BUILD(Str :$type!,
		    CipherName :$algorithm!,
		    |c) {
	self.build-gcrypt( $type.lc, $algorithm.lc, |c);
    }

    multi submethod build-gcrypt(
	$!type where 'cipher',
	CipherName $cipher-name,
	ModeName :$mode is copy,
	Bool :$secure,
	Bool :$enable-sync,
    ) {
	my gcry_uint $flags = 0;
	$flags +|= GCRY_CIPHER_SECURE if $secure;
	$flags +|= GCRY_CIPHER_ENABLE_SYNC if $enable-sync;

	self!init-library();

	my gcry_int $cipher-algo = gcry_cipher_map_name($cipher-name);
	die "Unknown cipher algorithm $cipher-name"
	    unless $cipher-algo;
	$!blklen = gcry_cipher_get_algo_blklen($cipher-algo);
	$!keylen = gcry_cipher_get_algo_blklen($cipher-algo);
	$mode //= $!blklen > 1 ?? 'cbc' !! 'stream';
	$!mode = self!map-cipher-mode($mode);
	my $h-ptr = CArray[gcry_cipher_handle].new;
	$h-ptr[0] = gcry_cipher_handle;
	$!err //= gcry_cipher_open($h-ptr, $cipher-algo, $!mode, $flags);
	$!h = $h-ptr[0];
	warn { :$!err, :$!h }.perl;
    }

    multi method start(Action $!action) {
	$!buffer = CArray[uint8].new;
	$!buffer[$!blklen - 1] = 0;
	$!need-to-call-finish = True;    
    }

    multi method setkey(Str $key, Str :$enc = 'latin-1') {
	$.setkey( $key.encode($enc) );
    }
    multi method setkey($key where {$.type eq 'cipher'}) {
	my $k = CArray[uint8].new: $key;
	$k[$.keylen - 1] = 0
	    unless $k.elems >= $.keylen-1;
	$!err = gcry_cipher_setkey($!h, $k, $.keylen);
    }

    multi method setiv(Str $key, Str :$enc = 'latin-1') {
	$.setiv( $key.encode($enc) );
    }
    multi method setiv(|c) {
	my $iv = CArray[uint8].new(|c);
	$iv[$.keylen - 1] = 0
	    unless $iv.elems >= $.keylen-1;
	$!err = gcry_cipher_setiv($!h, $iv, $.keylen);
    }

}


