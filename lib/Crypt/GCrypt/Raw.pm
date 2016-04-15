use v6;

class Crypt::GCrypt::Raw {
    use NativeCall;
    use NativeCall::Types;

    sub find-lib is export(:find-lib) {
	$*VM.platform-library-name('gcrypt'.IO).Str;
    }

    my role Alloced[&destroy-sub] {
	submethod DESTROY {
	    &destroy-sub(self);
	}
    }

    #| see gcrypt.h
    my constant gcry_cipher_hd_t is export(:types, :DEFAULT) = OpaquePointer;
    my constant gcry_md_hd_t is export(:types, :DEFAULT) = OpaquePointer;
    my constant gcry_error_t is export(:types, :DEFAULT) = OpaquePointer;
    our sub gcry_check_version(Pointer $null-pointer?)
        returns Str
        is export(:subs, :DEFAULT)
        is native(&find-lib) { * }

    our sub gcry_cipher_map_name(Str $name)
        returns size_t
        is export(:subs, :DEFAULT)
        is native(&find-lib) { * }

    our sub gcry_md_map_name(Str $name)
        returns size_t
        is export(:subs, :DEFAULT)
        is native(&find-lib) { * }

    our sub gcry_cipher_get_algo_keylen(size_t $algo)
        returns size_t
        is export(:subs, :DEFAULT)
        is native(&find-lib) { * }

    our sub gcry_cipher_get_algo_blklen(size_t $algo)
        returns size_t
        is export(:subs, :DEFAULT)
        is native(&find-lib) { * }

}
