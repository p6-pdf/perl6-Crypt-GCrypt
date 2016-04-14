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


}
