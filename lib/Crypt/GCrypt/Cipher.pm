use v6;

use Crypt::GCrypt :xs;

class Crypt::GCrypt::Cipher is Crypt::GCrypt {
    use Crypt::GCrypt::Raw :ALL, :memcpy, :memset;
    use NativeCall;

    #--

    my enum Action is export(:Action) < Encrypting Decrypting >;
    my enum Padding is export(:Padding) < NoPadding StandardPadding NullPadding SpacePadding >;
    has Action $!action;
    has Padding $!padding = StandardPadding;
    has gcry_cipher_hd_t $!h;
    has gcry_int $!mode;
    has CArray $!buffer;
    has size_t $!buflen;
    has size_t $.blklen;
    has size_t $.keylen;
    has Bool $!need-to-call-finish;
    has Bool $!buffer-is-decrypted;

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

    our sub cipher_algo_available(Str $name --> Bool) {
	? gcry_cipher_map_name($name.lc)
    }
    subset CipherName of Str where { gcry_cipher_map_name($_) }

    submethod BUILD(
	CipherName :$algorithm!,
	Str :$mode,
	Padding :$!padding = StandardPadding,
	Bool :$secure,
	Bool :$enable-sync,
    ) {
	my gcry_uint $flags = 0;
	$flags +|= GCRY_CIPHER_SECURE if $secure;
	$flags +|= GCRY_CIPHER_ENABLE_SYNC if $enable-sync;

	my gcry_int $cipher = gcry_cipher_map_name($algorithm);
	$!blklen = gcry_cipher_get_algo_blklen($cipher);
	$!keylen = gcry_cipher_get_algo_keylen($cipher);
	my CipherMode $mode-name = $mode // $!blklen > 1 ?? 'cbc' !! 'stream';
	$!mode = self!map-cipher-mode($mode-name);
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

    multi method setkey(Str $key, Str :$enc = 'latin-1') {
	$.setkey( $key.encode($enc) );
    }
    multi method setkey($mykey is copy) {
        unless $mykey.isa(CArray) {
	    $mykey = CArray[uint8].new: $mykey.list;
	    $mykey[$!keylen] = 0;
	}
	$.err = gcry_cipher_setkey($!h, $mykey+0, $!keylen);
    }

    multi method setiv(Str $key, Str :$enc = 'latin-1') {
	$.setiv( $key.encode($enc) );
    }
    multi method setiv(|c) {
	my $iv = CArray[uint8].new(|c);
	$iv[$!blklen] = 0
	    unless $iv.elems >= $!blklen;
	$.err = gcry_cipher_setiv($!h, $iv+0, $!blklen);
    }

    multi method encrypt(CArray $ibuf, uint $ilen = $ibuf.elems) {
	die "start('encrypting') was not called"
	    unless $!action.defined && $!action == Encrypting;

	if $!padding == NoPadding {
	    die "'NoPadding' padding requires that input to .encrypt() is supplied as a multiple of blklen"
	        unless $ilen %% $!blklen;
	}

	my $curbuf = xs-newz($ilen + $!buflen);
	memcpy($curbuf+0, $!buffer+0, $!buflen);
	memcpy($curbuf + $!buflen, $ibuf+0, $ilen);

	if (my int $len = $ilen + $!buflen)  %%  $!blklen {
	    $len = $ilen + $!buflen;
	    $!buffer[0] = 0;
	    $!buflen = 0;
	}
	else {
	    $len -= $ilen + $!buflen;
	    my $tmpbuf = xs-newz($len);
            memcpy($tmpbuf+0, $curbuf+0, $len);
	    my int $n = $ilen + $!buflen - $len;
	    xs-realloc($!buffer, $n)
		unless $!buffer.elems >= $n;
	    memcpy($!buffer+0, $curbuf + $len, $n);
            $!buflen += $ilen - $len;
	    $curbuf = $tmpbuf;
	}
	my \obuf = xs-newz($len);
	$.err = gcry_cipher_encrypt($!h, obuf+0, $len, $curbuf+0, $len)
            if $len;

	obuf;
    }
    multi method encrypt($ibuf where List|Blob, |c) {
        $.encrypt( CArray[uint8].new($ibuf), |c);
    }
    multi method encrypt(Str $in, Str :$enc = 'latin-1') {
	$.encrypt( $in.encode($enc) );
    }
    multi method encrypt(@buf, |c) {
        $.encrypt( CArray[uint8].new: @buf, |c);
    }

    method !finish-encrypting {
        $!need-to-call-finish = False;
        if $!buflen < $!blklen {
            my int $rlen = $!blklen - $!buflen;
            my $tmpbuf = xs-newz($!buflen + $rlen);
            memcpy($tmpbuf+0, $!buffer+0, $!buflen);
            given $!padding {
                when StandardPadding {
                    memset( $tmpbuf + $!buflen, $rlen, $rlen);
                }
                when NullPadding {
                    memset( $tmpbuf + $!buflen, 0, $rlen);
                }
                when SpacePadding {
                    constant Sp = ' '.ord;
                    memset( $tmpbuf + $!buflen, Sp, $rlen);
                }
            }
            $!buffer = $tmpbuf;
        }
        elsif $!padding == NullPadding && $!blklen == 8 {
            my $tmpbuf = xs-newz($!buflen + 8);
            memcpy($tmpbuf+0, $!buffer+0, $!buflen);
            memset( $tmpbuf + $!buflen, 0, 8);
            $!buffer = $tmpbuf;
        }
        my \obuf = xs-newz($!blklen);
        $.err =  gcry_cipher_encrypt($!h, obuf+0, $!blklen, $!buffer+0, $!blklen);
        $!buffer[0] = 0;
        $!buflen = 0;
        obuf;
    }

    sub _dump_buf($buf, $len) {
        $*ERR.print: "[ ";
        loop (my $i = 0; $i < $len; $i++) {
            my uint8 $n = $buf[$i];
            $*ERR.print: sprintf("%x, ", $n);
        }
        $*ERR.print: "]\n";        
    }

    multi method decrypt(CArray $ibuf, uint $ilen = $ibuf.elems) {
	die "start('decrypting') was not called"
	    unless $!action.defined && $!action == Decrypting;
        die "input must be a multiple of blklen"
            unless $ilen && $ilen %% $!blklen;
        # Concatenate buffer and input to get total length of ciphertext
        my $total-len = $!buflen + $ilen;
        my $ciphertext = xs-newz($total-len);
        xs-move($!buffer+0, $ciphertext+0, $!buflen);
        xs-move($ibuf+0, $ciphertext + $!buflen, $ilen);
        my $offset = $!buffer-is-decrypted ?? $!buflen !! 0;
        my $len = $total-len - $!blklen;
        xs-move($ciphertext + $len, $!buffer+0, $!blklen);
        $!buflen = $!blklen;
        my $obuf = xs-newz($len);
        xs-move($ciphertext+0, $obuf+0, $offset);
        if $len - $offset > 0 {
            $.err = gcry_cipher_decrypt($!h, $obuf + $offset, $len - $offset, $ciphertext + $offset, $len - $offset);
        }
        $.err = gcry_cipher_decrypt($!h, $!buffer+0, $!buflen, Pointer, 0);
        $!buffer-is-decrypted = True;
        without self!find-padding( $!buffer, $!buflen) {
            xs-realloc($obuf, $len + $!buflen); #extend
            xs-move($!buffer+0, $obuf + $len, $!buflen);
            $len += $!buflen;
            $!buffer[0] = 0;
            $!buflen = 0;
            $!buffer-is-decrypted = False;
        }
        xs-realloc($obuf, $len);
        $obuf;
    }
    multi method decrypt($ibuf where List|Blob, |c) {
        $.decrypt( CArray[uint8].new($ibuf), |c);
    }
    multi method decrypt(Str $in, Str :$enc = 'latin-1') {
	$.decrypt( $in.encode($enc) );
    }
    multi method decrypt(@buf, |c) {
        $.decrypt( CArray[uint8].new: @buf, |c);
    }

    method !find-padding(CArray $buf, int $len = $buf.elems) {
        return Nil unless $len > 0;
        given $!padding {
            when StandardPadding {
                my uint8 $p = $buf[$len-1];
                return Nil
                    unless 0 < $p <= $len;

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
        loop (my int $i = $len-1; $buf[$i] == $ichr; $i--) {
            $offset = $i;
        }
        $offset;
    }

    method !finish-decrypting {
        $!need-to-call-finish = False;
        my $obuf = xs-newz( $!buflen );
        my $ret-len = $!buflen;
        if $!buflen > 0 {
            if $!buffer-is-decrypted {
                xs-move( $!buffer+0, $obuf+0, $!buflen );
            }
            else {
                $.err = gcry_cipher_decrypt($!h, $obuf+0, $ret-len, $!buffer+0, $!buflen );
            }
            $!buffer[0] = 0;
            $!buflen = 0;

            with self!find-padding($obuf, $ret-len) -> $len {
                xs-realloc($obuf, $len);
            }

        }
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
        my &meth = method ($stuff, :$key!, :$iv, :$action='decrypt', |c) {
            my $obj = self.new( :$algorithm, |c );
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
