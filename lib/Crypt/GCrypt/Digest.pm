use v6;

use Crypt::GCrypt;

class Crypt::GCrypt::Digest is Crypt::GCrypt {

    use Crypt::GCrypt::Raw;
    use NativeCall;
    
    has gcry_md_hd_t $!h;

    our sub digest_algo_available(Str $name --> Bool) {
	? gcry_md_map_name($name.lc)
    }
    
    subset DigestName of Str where { gcry_md_map_name($_) }

    submethod BUILD(DigestName :$algorithm!, |c) {
	self.build-digest( $algorithm, |c);
    }

    multi submethod build-digest(
	DigestName $digest-name,
        Bool :$secure,
        :$hmac where Str|CArray|List,
    ) {
        my gcry_uint $flags = 0;
        $flags +|= GCRY_MD_FLAG_SECURE if $secure;
        $flags +|= GCRY_MD_FLAG_HMAC with $hmac;
        my gcry_int $digest-algo = gcry_md_map_name($digest-name);
	die "Unknown digest algorithm $digest-name"
	    unless $digest-algo;

        my $h-buf = CArray[gcry_md_hd_t].new;
	$h-buf[0] = gcry_md_hd_t;
	self.err = gcry_md_open($h-buf, $digest-algo, $flags);
	$!h = $h-buf[0];
        self.setkey($_) with $hmac;
    }

    multi method setkey(Str $key, Str :$enc = 'latin-1') {
	$.setkey( $key.encode($enc) );
    }
    multi method setkey($mykey is copy) {
        unless $mykey.isa(CArray) {
	    $mykey = CArray[uint8].new: $mykey.list;
	}
	$.err = gcry_md_setkey($!h, $mykey+0, $mykey.elems);
    }


}
