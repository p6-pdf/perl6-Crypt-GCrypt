#
# Test compability with Perl5 Digest::MD5
#

use Test;
use Crypt::GCrypt::Digest;
use newline :lf;

plan 3;
my @cases = (
    "Hello World"  , "\x[B1]\x[0A]\x[8D]\x[B1]\x[64]\x[E0]\x[75]\x[41]\x[05]\x[B7]\x[A9]\x[9B]\x[E7]\x[2E]\x[3F]\x[E5]",
    "Hello World\n", "\x[E5]\x[9F]\x[F9]\x[79]\x[41]\x[04]\x[4F]\x[85]\x[DF]\x[52]\x[97]\x[E1]\x[C3]\x[02]\x[D2]\x[60]",
    "Zs\o[363]fia",  "\x[36]\x[99]\x[AC]\x[C0]\x[BA]\x[E1]\x[8C]\x[60]\x[0C]\x[6B]\x[AE]\x[B9]\x[57]\x[E7]\x[81]\x[93]", # 8 bit
);

for @cases -> $values, $expected {
    is Crypt::GCrypt::Digest.md5($values).decode("latin-1"), $expected, "MD5 class method of '$values'";
}
