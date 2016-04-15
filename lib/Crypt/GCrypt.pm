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

    our sub cipher_algo_available(Str $name --> Bool) {
	? gcry_cipher_map_name($name)
    }

    our sub digest_algo_available(Str $name --> Bool) {
	? gcry_md_map_name($name)
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


