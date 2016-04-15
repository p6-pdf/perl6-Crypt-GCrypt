use v6;
use Test;
use Crypt::GCrypt;

my $c = Crypt::GCrypt.new(
    :type<cipher>,
    :algorithm<aes>,
    :mode<cbc>,
    :padding<null>,
);

ok defined $c && $c.isa(Crypt::GCrypt);
is $c.keylen, 16;
is $c.blklen, 16;

done-testing;
