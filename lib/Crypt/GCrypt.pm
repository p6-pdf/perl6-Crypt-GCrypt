use v6;

class X::Crypt::GCrypt::Error is Exception {
    has Str  $.message is required;
    has UInt $.domain;
    has UInt $.status;
    method message {"GCrypt error: {$.message}"}
}
use v6;

class Crypt::GCrypt {
    use Crypt::GCrypt::Raw :ALL, :memcpy, :memset;
    use NativeCall;

    multi sub infix:<+>(Pointer $p, UInt $n) {
	die "Can't do arithmetic with a void pointer"
	    unless $p.can('of');
	my \type = $p.of;
	die "Can't do arithmetic with a void pointer"
	    if type ~~ void;
	my $pn = $p.new: +$p + $n;
	nativecast(Pointer[$p.of], $pn);
    }

    sub newz(UInt $len) returns CArray {
        my $buf = CArray[uint8].new;
        $buf[$len-1] = 0;
        $buf;
    }

    our $Sec-Mem-Size = 2 ** 15;

    has Str $.type where 'cipher'; #|todo: asymm digest
    my enum Action  is export(:Action) < Encrypting Decrypting >;
    my enum Padding  is export(:Padding) < NoPadding StandardPadding NullPadding SpacePadding >;
    has Action $!action;
    has Padding $!padding = NoPadding;
    has gcry_cipher_hd_t $!h;
    has gcry_error_t $!err;
    has gcry_int $!mode;
    has CArray $!buffer;
    has size_t $!buflen;
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
    subset CipherMode of Str where %CIPHER-MODE{$_}:exists;

    method !map-cipher-mode(CipherMode $mode --> gcry_cipher_modes ) {
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
	CipherMode :$mode is copy,
	Padding :$!padding = NoPadding,
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
    }

    multi method start('encrypting') { $.start(Encrypting) }
    multi method start('decrypting') { $.start(Decrypting) }
    multi method start(Action $!action) {
	$!buffer = newz($!blklen);
	$!need-to-call-finish = True;    
    }

    multi method setkey(Str $key, Str :$enc = 'latin-1') {
	$.setkey( $key.encode($enc) );
    }
    multi method setkey($mykey is copy where {$.type eq 'cipher'}) {
        if +$mykey < $!keylen || !$mykey.isa(CArray) {
	    $mykey = CArray[uint8].new: $mykey.list;
	    $mykey[$!keylen] = 0
	}
	$!err = gcry_cipher_setkey($!h, $mykey, $!keylen);
    }

    multi method setiv(Str $key, Str :$enc = 'latin-1') {
	$.setiv( $key.encode($enc) );
    }
    multi method setiv(|c) {
	my $iv = CArray[uint8].new(|c);
	$iv[$!keylen] = 0
	    unless $iv.elems >= $!keylen-1;
	$!err = gcry_cipher_setiv($!h, $iv, $!keylen);
    }

    multi method encrypt(Str $in, Str :$enc = 'latin-1') {
	$.encrypt( $in.encode($enc) );
    }
    multi method encrypt(Blob $ibuf, |c) {
        $.encrypt( CArray[uint8].new($ibuf), |c);
    }
    multi method encrypt(CArray $ibuf, uint $ilen = $ibuf.elems) {
	die "start('encrypting') was not called"
	    unless $!action == Encrypting;

	if $!padding == NoPadding {
	    die "'NoPadding' padding requires that input to .encrypt() is supplied as a multiple of blklen"
	        unless $ilen %% $!blklen;
	}

	my $curbuf = newz($ilen + $!buflen);
	memcpy($curbuf.Pointer, $!buffer.Pointer, $!buflen);
	memcpy($curbuf.Pointer + $!buflen, $ibuf.Pointer, $ilen);

	if (my int $len = $ilen + $!buflen)  %%  $!blklen {
	    $!buffer[0] = 0;
	    $!buflen = 0;
	}
	else {
	    $len -= $ilen + $!buflen;
	    my \tmpbuf = newz($len);
            memcpy(tmpbuf.Pointer, $curbuf.Pointer, $len);
	    memcpy($!buffer.Pointer, $curbuf.Pointer + $len, ($ilen+$!buflen) - $len);
            $!buflen += $ilen - $len;
	    $curbuf = tmpbuf;
	}
	my \obuf = newz($len);
	$.err = gcry_cipher_encrypt($.h, \obuf, $len, $curbuf, $len)
            if $len;

	obuf;
    }

    method !finish-encrypting {
        if $!buflen < $!blklen {
            my int $rlen = $!blklen - $!buflen;
            my \tmpbuf = newz($!buflen + $rlen);
            memcpy(tmpbuf.Pointer, $!buffer.Pointer, $!buflen);
            given $!padding {
                when StandardPadding {
                    memset( tmpbuf.Pointer + $!buflen, $rlen, $rlen);
                }
                when NullPadding {
                    memset( tmpbuf.Pointer + $!buflen, 0, $rlen);
                }
                when SpacePadding {
                    constant Sp = ' '.ord;
                    memset( tmpbuf.Pointer + $!buflen, Sp, $rlen);
                }
            }
            $!buffer := tmpbuf;
        }
        elsif $!padding == NullPadding && $!blklen == 8 {
            my \tmpbuf = newz($!buflen + 8);
            memcpy(tmpbuf.Pointer, $!buffer.Pointer, $!buflen);
            memset(tmpbuf.Pointer + $!buflen, 0, 8);
        }
        my \obuf = newz($!blklen);
        $!err =  gcry_cipher_encrypt($!h, obuf, $!blklen, $!buffer, $!blklen);
        $!buffer[0] = 0;
        $!buflen = 0;
        obuf;
    }

    method !finish-decrypting {
        ...
    }

    method finish {
	die "Can't call finish when doing non-cipher operations"
            unless $!type eq 'cipher';
        $!need-to-call-finish = False;
        given $!action {
            when Encrypting { self!finish-encrypting }
            when Decrypting { self!finish-decrypting }
        }
    }
}
