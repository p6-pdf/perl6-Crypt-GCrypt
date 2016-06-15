use v6;
use Test;
use Crypt::GCrypt::Cipher :Padding;
use Crypt::GCrypt::Raw;
use NativeCall;

my $version = Crypt::GCrypt::Cipher.gcrypt-version;
diag "found LibGCrypt version: $version"; 
ok Crypt::GCrypt::Cipher.algo-available('aes'), 'aes available';
ok Crypt::GCrypt::Cipher.algo-available('arcfour'), 'arcfour available';
ok Crypt::GCrypt::Cipher.algo-available('twofish'), 'twofish available';

my $p = 'plain text';
my Buf $e0 .= new: [0xC7, 0x96, 0x84, 0x35, 0x58, 0xCE, 0xFA, 0x15, 0x7B, 0xF1, 0x08, 0xAB, 0x79, 0x82, 0x3A, 0x5A, ];

# --- #

my $c = Crypt::GCrypt::Cipher.new(
    :algorithm<aes>,
    :mode<cbc>,
    :padding(NullPadding),
);

ok defined $c && $c.isa(Crypt::GCrypt::Cipher);
is $c.keylen, 16;
is $c.blklen, 16;

$c.start('encrypting');
$c.setkey(my $key = "the key, the key");

my Buf $e .= new: $c.encrypt($p);
$e.append: $c.finish;

is-deeply $e, $e0;

$c.setiv;
$c.start('decrypting');
my Buf $d .= new: $c.decrypt($e);
$d.append: $c.finish.list;

is $d.decode('latin-1'), $p;

# --- #

$c = Crypt::GCrypt::Cipher.new(
    :algorithm<aes>,
    :mode<ecb>,
    :padding(NullPadding),
);

ok defined $c && $c.isa(Crypt::GCrypt::Cipher);
is $c.keylen, 16;
is $c.blklen, 16;

$c.start('encrypting');
$c.setkey($key = "the key, the key");

$e .= new: $c.encrypt($p);
$e.append: $c.finish;

is-deeply $e, $e0;

# --- #

if $version ge '1.6.0' {
    $c = Crypt::GCrypt::Cipher.new(
        :algorithm<twofish>,
        :padding(NullPadding),
    );
    is $c.keylen, 32;
    is $c.blklen, 16;
    $c.start('encrypting');
    $c.setkey($key);
    $c.setiv(my $iv = 'explicit iv');
    $e = Buf.new: $c.encrypt($p);
    $e.append: $c.finish;

    $c.start('decrypting');
    $c.setiv($iv);
    $d = Buf.new: $c.decrypt($e);
    $d.append: $c.finish;
    is $d.decode('latin-1'), $p;

    # --- #

    $c = Crypt::GCrypt::Cipher.new(
        :algorithm<arcfour>,
        :padding(NoPadding),
    );
    is $c.keylen, 16;
    is $c.blklen, 1;
    $c.start('encrypting');
    $c.setkey($key);
    $e = Buf.new: $c.encrypt($p);
    is-deeply [$e.list], [ 0x02, 0xa9, 0x8d, 0x20, 0xa1, 0x76, 0x72, 0x9e, 0xa7, 0xcd];

    $c.setkey($key);
    $c.start('decrypting');
    $d = Buf.new: $c.decrypt($e);
    $d.append: $c.finish;
    is $d.decode('latin-1'), $p;
}
else {
    skip "need GCrypt 1.6.0+ for arcfour & blowfish", 6;
}
# --- #
### 'none' padding

$c = Crypt::GCrypt::Cipher.new(
    :algorithm<aes>,
    :padding(NoPadding),
    );
$c.start('encrypting');
dies-ok { $c.encrypt('aaa'); $c.finish };
$c.start('encrypting');;
lives-ok {$c.encrypt('aaaaaaaaaaaaaaaa') ; $c.finish; };

# -- #
## encrypted and decrypted 'one-stop' methods
my %scheme = (
    :$key,
    algorithm => 'aes',
    mode => 'cbc',
    padding => NullPadding,
);
my $encrypted = Crypt::GCrypt::Cipher.encrypted( $p, |%scheme);
is-deeply $encrypted, $e0, '.encrypted';

my $decrypted = Crypt::GCrypt::Cipher.decrypted( $e0, |%scheme);
is-deeply $decrypted.decode('latin-1'), $p, '.decrypted';

done-testing;
