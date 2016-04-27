use v6;
use Test;
use Crypt::GCrypt :Padding;

my $c = Crypt::GCrypt.new(
    :type<cipher>,
    :algorithm<aes>,
    :mode<cbc>,
    :padding(NullPadding),
);

ok defined $c && $c.isa(Crypt::GCrypt);
is $c.keylen, 16;
is $c.blklen, 16;

$c.start('encrypting');
lives-ok {$c.setkey(my $key = "the key, the key")}, '.setkey';

my $p = 'plain text';
my Buf $e0 .= new: [0xC7, 0x96, 0x84, 0x35, 0x58, 0xCE, 0xFA, 0x15, 0x7B, 0xF1, 0x08, 0xAB, 0x79, 0x82, 0x3A, 0x5A, ];

my @e = $c.encrypt($p);
##$e.append: $c.finish;
warn @e.perl;

done-testing;
