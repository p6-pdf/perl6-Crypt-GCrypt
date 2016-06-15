use v6;

class X::Crypt::GCrypt::Error is Exception {
    has Str $.message is required;
    has Str $.source = "gcrypt";
    method message {"{$.source} error: {$.message}"}
}

class Crypt::GCrypt {
    use Crypt::GCrypt::Raw :ALL, :memcpy;
    use NativeCall;

    has gcry_error_t $!err;

    method err is rw {
        Proxy.new(
            FETCH => sub ($) { $!err },
            STORE => sub ($, $!err) {
                if $!err {
                    my Str $message = gcry_strerror($!err);
                    my Str $source  = gcry_strsource($!err);
                    die "{$source} error: {$message}";
                    ##my X::Crypt::GCrypt::Error $stat .= new( :$message, :$source );
                    ##$stat.throw;
                }
            })
    }

    our $Sec-Mem-Size = 2 ** 15;

    method !check-version($min-gcrypt-version = '1.5.3') returns Bool {
	state Str $gcrypt-version //= gcry_check_version();
	die "libgcrypt version mismatch (need: >= {$min-gcrypt-version}, got $gcrypt-version)"
	    unless $gcrypt-version ge $min-gcrypt-version;
        True;
    }

    method gcrypt-version{ self!check-version }

    method !init-library {
        self!check-version;
	my gcry_ctl_cmd $cmd;
	unless (gcry_control($cmd = GCRYCTL_INITIALIZATION_FINISHED_P)) {
	    #`{{ we just need to make sure that the right version is available
	         Why do it this way?  see 
                 /usr/share/doc/libgcrypt11-doc/html/Initializing-the-library.html#sample-use-suspend-secmem

                 We don't want to see any warnings, e.g. because we have not yet
                 parsed program options which might be used to suppress such
                 warnings.
            }}
            gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
     
            #`{{ Allocate a pool of 32k secure memory.  This make the secure memory
                 available and also drops privileges where needed.  

                 This mirrors changes made in libgcrypt 1.4.3, to auto-initialize
                 the library with 32KB of secure memory if no other initialization
                 has been done.

            }}
            gcry_control2(GCRYCTL_INIT_SECMEM, $Sec-Mem-Size, 0);
     
            #`{{ It is now okay to let Libgcrypt complain when there was/is
                 a problem with the secure memory.
            }}
            gcry_control(GCRYCTL_RESUME_SECMEM_WARN);

            gcry_control(GCRYCTL_INITIALIZATION_FINISHED);

	}
    }

    submethod BUILD() {
	self!init-library();
    }

    #++ replacements for some Perl XS macros

    sub xs-newz(UInt $len) returns CArray is export(:xs) {
        my $buf = CArray[uint8].new;
        $buf[$len-1] = 0 if $len;
        $buf;
    }

    sub xs-move(Pointer $from, Pointer $to, $len) is export(:xs) {
        memcpy($to, $from, $len);
    }

    sub xs-realloc(CArray $buf is rw, $len) is export(:xs) {
        if $len < $buf.elems {
            my \tmp = xs-newz($len);
            memcpy( tmp+0, $buf+0, $len);
            $buf = tmp;
        }
        elsif $len > $buf.elems {
            $buf[$len-1] = 0;
        }
        $buf;
    }

    proto sub xs-array($) is export(:xs) {*}
    multi sub xs-array(CArray:D $stuff) { $stuff }
    multi sub xs-array(Str $stuff, Str :$enc = 'latin-1') {
        CArray[uint8].new: $stuff.encode($enc).list;
    }
    multi sub xs-array($stuff is copy) is default {
	CArray[uint8].new: +$stuff ?? $stuff.list !! 0;
    }
    sub xs-ptr($stuff, |c) is export(:xs) { xs-array($stuff, |c) + 0 }
    
    multi sub infix:<+>(Pointer $p, UInt $n) returns Pointer is export(:xs) {
	die "Can't do arithmetic with a void pointer"
	    unless $p.can('of');
	my \type = $p.of;
	die "Can't do arithmetic with a void pointer"
	    if type ~~ void;
	my $pn = $p.new: +$p + $n;
	nativecast(Pointer[$p.of], $pn);
    }
    multi sub infix:<+>(CArray $c, UInt $n) returns Pointer is export(:xs) {
        die "Pointer out of range: $n > {$c.elems}" if $n > $c.elems;
        nativecast(Pointer[$c.of], $c) + $n;
    }

}
