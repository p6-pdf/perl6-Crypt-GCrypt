use v6;

use Crypt::GCrypt :xs;

class Crypt::GCrypt::Digest is Crypt::GCrypt {

    use Crypt::GCrypt::Raw :ALL,:memcpy;
    use NativeCall;
    
    has gcry_md_hd_t $!h;
    has uint32 $.digest-length;

    method algo-available(Str $name --> Bool) {
	given gcry_md_map_name($name.lc) {
            when * > 0 { ! gcry_md_algo_info($_, GCRYCTL_TEST_ALGO) }
            default { False }
        }
    }
    subset DigestName of Str where { gcry_md_map_name($_) }

    submethod BUILD(
	DigestName :$algorithm,
        Bool :$secure,
        :$hmac,
    ) {
        my uint32 $flags = 0;
        $flags +|= GCRY_MD_FLAG_SECURE if $secure;
        $flags +|= GCRY_MD_FLAG_HMAC with $hmac;
        my int32 $digest = gcry_md_map_name($algorithm);
        $!digest-length = gcry_md_get_algo_dlen($digest);

        my $h-buf = CArray[gcry_md_hd_t].new;
	$h-buf[0] = gcry_md_hd_t;
	self.err = gcry_md_open($h-buf, $digest, $flags);
	$!h = $h-buf[0];
        self.setkey($_) with $hmac;
    }

    multi method setkey(Str $key, Str :$enc = 'latin-1') {
	$.setkey( $key.encode($enc) );
    }
    multi method setkey($mykey is copy) {
	$.err = gcry_md_setkey($!h, xs-ptr($mykey), $mykey.elems);
    }

    multi method write(Str $stuff, Str :$enc = 'latin-1') {
	$.write( $stuff.encode($enc) );
    }
    multi method write( $stuff is copy ) {
	gcry_md_write($!h, xs-ptr($stuff), $stuff.elems);
    }

    method read() {
        my Pointer $out = gcry_md_read($!h, 0);
        my $buf = xs-newz( $!digest-length );
        memcpy( $buf+0, $out, $!digest-length );
        $buf;
    }

    multi method FALLBACK(DigestName $algorithm, |c --> Buf) {
        my int $algo = gcry_md_map_name($algorithm);
        my int $digest-length = gcry_md_get_algo_dlen($algo);
        my &meth = method ($stuff, |p) {
            my $ibuf = xs-array($stuff, |p);
            my $obuf = xs-newz( $digest-length );
            gcry_md_hash_buffer( $algo, $obuf+0, $ibuf+0, $ibuf.elems);
            Buf.new: $obuf;
        };
        self.WHAT.^add_method($algorithm, &meth );
        self."$algorithm"(|c);
    }

}
