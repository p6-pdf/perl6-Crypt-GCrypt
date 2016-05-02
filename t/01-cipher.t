use v6;
use Test;
use Crypt::GCrypt :Padding;

my $c = Crypt::GCrypt.new(
    :type<cipher>,
    :algorithm<aes>,
    :mode<cbc>,
    :padding(NullPadding),
);

ok Crypt::GCrypt::cipher_algo_available('aes');
ok Crypt::GCrypt::cipher_algo_available('arcfour');
ok Crypt::GCrypt::cipher_algo_available('twofish');

ok defined $c && $c.isa(Crypt::GCrypt);
is $c.keylen, 16;
is $c.blklen, 16;

$c.start('encrypting');
$c.setkey(my $key = "the key, the key");

my $p = 'plain text';
my uint8 @e0 = [0xC7, 0x96, 0x84, 0x35, 0x58, 0xCE, 0xFA, 0x15, 0x7B, 0xF1, 0x08, 0xAB, 0x79, 0x82, 0x3A, 0x5A, ];

my uint8 @e = $c.encrypt($p).list;
@e.append: $c.finish.list;

is-deeply @e, @e0;

$c.setiv;
$c.start('decrypting');
my @d = $c.decrypt(@e);
@d.append: $c.finish.list;

done-testing;
