use v6;

class X::Crypt::GCrypt::Error is Exception {
    has Str  $.message is required;
    has UInt $.domain;
    has UInt $.status;
    method message {"GCrypt error: {$.message}"}
}
use v6;

class Crypt::GCrypt {
    use Crypt::GCrypt::Raw :subs, :types;
    use NativeCall;
    
    has int $!type;
    has int $!action;
    has gcry_cipher_hd_t $!h;
    has gcry_md_hd_t $!h-md;
    has gcry_error_t $!error;
    has int $!mode;
    has CArray $buffer;
    has size_t $.blklen;
    has size_t $.keylen;

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
	:$type = 'cbc',
    ) {
	my int $algo = gcry_cipher_map_name($algorithm.lc)
	    or die "Unknown cipher algorithm $algorithm";
	$!blklen = gcry_cipher_get_algo_blklen($algo);
	$!keylen = gcry_cipher_get_algo_blklen($algo);
    }

    multi method start('encrypting') {
	...
    }
    method set-key($key) {
	...
    }
    method set-iv($vect) {
	...
    }

}


