use v6;

use Crypt::GCrypt :xs;

class Crypt::GCrypt::Cipher is Crypt::GCrypt {
    use Crypt::GCrypt::Raw :ALL, :memcpy, :memset;
    use NativeCall;

    #--

    my enum Action is export(:Action) < Encrypting Decrypting >;
    my enum Padding is export(:Padding) < NoPadding StandardPadding NullPadding SpacePadding >;
    has Str $!algorithm;
    has Action $!action;
    has Padding $!padding = StandardPadding;
    has gcry_cipher_hd_t $!h;
    has int32 $!mode;
    has CArray $!buffer;
    has size_t $!buflen;
    has size_t $.blklen;
    has size_t $.keylen;
    has Bool $!need-to-call-finish;

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

    method algo-available(Str $name --> Bool) {
	given gcry_cipher_map_name($name.lc) {
            when * > 0 { ! gcry_cipher_algo_info($_, GCRYCTL_TEST_ALGO) }
            default { False }
        }
    }

    subset CipherName of Str where { gcry_cipher_map_name($_) }

    submethod BUILD(
	CipherName :$!algorithm!,
	Str :mode($mode-name) is copy,
	Padding :$padding,
	Bool :$secure,
	Bool :$enable-sync,
    ) {
	my uint32 $flags = 0;
	$flags +|= GCRY_CIPHER_SECURE if $secure;
	$flags +|= GCRY_CIPHER_ENABLE_SYNC if $enable-sync;

	my int32 $cipher = gcry_cipher_map_name($!algorithm);
	$!blklen = gcry_cipher_get_algo_blklen($cipher);
	$!keylen = gcry_cipher_get_algo_keylen($cipher);
	$mode-name //= $!blklen > 1 ?? 'cbc' !! 'stream';
        die "invalid mode: $mode-name"
            unless $mode-name ~~ CipherMode;
	$!mode = self!map-cipher-mode($mode-name);
        $!padding = $padding // ($!mode == GCRY_CIPHER_MODE_STREAM ?? NoPadding !! StandardPadding);
        die "Padding is not supported for stream-mode"
            if  $!mode == GCRY_CIPHER_MODE_STREAM && $!padding != NoPadding;
	my $h-buf = CArray[gcry_cipher_hd_t].new;
	$h-buf[0] = gcry_cipher_hd_t;
	self.err = gcry_cipher_open($h-buf, $cipher, $!mode, $flags);
	$!h = $h-buf[0];
    }

    multi method start(Str $_) {
        when 'encrypting'|'encrypt' { $.start(Encrypting) }
        when 'decrypting'|'decrypt' { $.start(Decrypting) }
        default { die "can't start: $_" }
    }
    multi method start(Action $!action) {
	$!buffer = xs-newz($!blklen);
        $!buflen = 0;
	$!need-to-call-finish = True;    
    }

    method setkey($k, $len? is copy, |c) {
        my $key = xs-array($k, |c);
        $len //= $key.elems;
        $key[$!keylen-1] = 0 if $key.elems < $!keylen;
        $.err = gcry_cipher_setkey($!h, $key+0, $len);
    }

    method setiv($k=[], |c) {
	my $iv = xs-array($k, |c);
        $iv[$!blklen-1] = 0 if $iv.elems < $!blklen;
	$.err = gcry_cipher_setiv($!h, $iv+0, $!blklen);
    }

    method encrypt($buf, |c) {
	die "start('encrypting') was not called"
	    unless $!action.defined && $!action == Encrypting;
        my $ibuf = xs-array($buf, |c);
        my uint $ilen = $ibuf.elems;
	my int $len = $ilen + $!buflen;
	my $curbuf = xs-newz($len);
	memcpy($curbuf+0, $!buffer+0, $!buflen) if $!buflen;
	memcpy($curbuf + $!buflen, $ibuf+0, $ilen) if $ilen;

	if ($len  %%  $!blklen) {
	    # exact fit
	    $!buffer[0] = 0;
	    $!buflen = 0;
	}
	else {
	    # partial block - carry forward
	    $!buflen = $len mod $!blklen;
	    $len -= $!buflen;
	    memcpy($!buffer+0, $curbuf+$len, $!buflen);
	}

	my \obuf = xs-newz($len);
	$.err = gcry_cipher_encrypt($!h, obuf+0, $len, $curbuf+0, $len)
            if $len;

	obuf;
    }

    sub pad($buffer is rw, $buflen, $blklen, :$padding = StandardPadding) {
        my int $rlen = $blklen - $buflen;
        if $padding == NoPadding {
            die "'NoPadding' padding requires that input to .encrypt() issupplied as a multiple of blklen"
                if $rlen;
        }
        elsif $rlen {
            my $tmpbuf = xs-newz($blklen);
            memcpy($tmpbuf+0, $buffer+0, $buflen);
            my $pad = do given $padding {
                when StandardPadding { $rlen }
                when NullPadding     { 0 }
                when SpacePadding    { ' '.ord };
                default { die "unknown padding mode: $_" }
            };
            memset( $tmpbuf + $buflen, $pad, $rlen);
            $buffer = $tmpbuf;
        }
    }
    
    method !finish-encrypting {
        $!need-to-call-finish = False;
	my $len = 0;
        if $!buflen || $!padding == StandardPadding {
            pad($!buffer, $!buflen, $len = $!blklen, :$!padding);
        }
        elsif $!padding == NullPadding && $!blklen == 8 {
            pad($!buffer, $!buflen, $len = $!blklen+8, :$!padding);
        }
        my \obuf = xs-newz($len);
        $.err =  gcry_cipher_encrypt($!h, obuf+0, $len, $!buffer+0, $len)
	    if $len;
        $!buffer[0] = 0;
        $!buflen = 0;
        obuf;
    }

    method decrypt($buf, |c) {
	die "start('decrypting') was not called"
	    unless $!action.defined && $!action == Decrypting;
        my $ibuf = xs-array($buf, |c);
        my $ilen = $ibuf.elems;
        die "input must be a multiple of blklen"
            unless $ilen %% $!blklen;
        # Concatenate buffer and input to get total length of ciphertext
        my $obuf = xs-newz($ilen + $!buflen);
        memcpy($obuf+0, $!buffer+0, $!buflen) if $!buflen;
        if $ilen {
            memcpy($obuf+$!buflen, $ibuf+0, $ilen);
            $.err = gcry_cipher_decrypt($!h, $obuf + $!buflen, $ilen, Pointer, 0);
        }
    
        with self!find-padding( $obuf, $ilen) -> $rlen {
            # possible padding - hold back
            $!buflen = $ilen - $rlen;
            $!buffer = xs-newz($!buflen);
            memcpy($!buffer+0, $obuf + $rlen, $!buflen);
            xs-realloc($obuf, $rlen);
        }
        else {
            $!buflen = 0;
            $!buffer[0] = 0;
        }

        $obuf;
    }

    method !find-padding(CArray $buf, int $len = $buf.elems) {
        return Nil unless $len > 0 && $!padding != NoPadding;
        given $!padding {
            when StandardPadding {
                my uint8 $p = $buf[$len-1];
                return Nil
                    unless 0 < $p <= $!blklen;

                for 2 .. $p {
                    return Nil unless $buf[$len - $_] == $p;
                }
                $len - $p;
            }
            when NullPadding {
                self!find-padding-chr($buf, $len, 0);
            }
            when SpacePadding {
                self!find-padding-chr($buf, $len, 32);
            }
        }
    }

    method !find-padding-chr($buf, $len, $ichr) {
        my $offset;
        my uint $max = $!blklen;
        loop (my int $i = $len-1; $max-- && $buf[$i] == $ichr; $i--) {
            $offset = $i;
        }
        $offset;
    }

    method !finish-decrypting {
        $!need-to-call-finish = False;
        my $obuf = xs-newz( 0 );
        $!buffer[0] = 0;
        $!buflen = 0;
        $obuf;
    }

    method finish {
        $!need-to-call-finish = False;
        given $!action {
            when Encrypting { self!finish-encrypting }
            when Decrypting { self!finish-decrypting }
        }
    }

    multi method FALLBACK(CipherName $algorithm, |c --> Buf) {
        my &meth = method ($stuff, :$key!, :$iv, :$action='decrypt', |p) {
            my $obj = self.new( :$algorithm, |p );
            $obj.setkey($key);
            $obj.setiv($_) with $iv;
            $obj.start($action);
            my $crypt = Buf.new: $obj."$action"($stuff);
            $crypt.append: $obj.finish;
            $crypt;
        };
        self.WHAT.^add_method($algorithm, &meth );
        self."$algorithm"(|c);
    }

    method encrypted($stuff, CipherName :$algorithm!, |c --> Buf) {
        self."$algorithm"($stuff, :action<encrypt>, |c);
    }

    method decrypted($stuff, CipherName :$algorithm!, |c --> Buf) {
        self."$algorithm"($stuff, :action<decrypt>, |c);
    }


}
