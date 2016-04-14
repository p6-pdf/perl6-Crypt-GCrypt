use v6;

class LibGnuPDF::Tie::Hash {
    use LibGnuPDF :types, :subs, :find-lib;
    use NativeCall;

    our sub pdf_hash_new(pdf_error_t)
        returns pdf_hash_t
        is export(:subs, :DEFAULT)
        is native(&find-lib) { * }

    our sub pdf_hash_key_p(pdf_hash_t,
                           CArray[pdf_char_t])
        returns pdf_bool_t
        is export(:subs, :DEFAULT)
        is native(&find-lib) { * }


}
