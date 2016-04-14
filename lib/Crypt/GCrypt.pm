use v6;

class X::Crypt::GCrypt::Error is Exception {
    has Str  $.message is required;
    has UInt $.domain;
    has UInt $.status;
    method message {"GCrypt error: {$.message}"}
}
use v6;

class Crypt::GCrypt {
    use Crypt::GCrypt::Raw :subs;
    
    has Str $.type;
    has Str $.algorithm;
    has Str $.mode;

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


