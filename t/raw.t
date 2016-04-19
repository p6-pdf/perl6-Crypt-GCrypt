use v6;
use Test;
use Crypt::GCrypt::Raw;

my $version = gcry_check_version;
ok $version, 'got version';
diag "gcrypt version: $version";
ok $version ge '1.6.0', 'gcrypt version is at least 1.6.0';
is gcry_cipher_map_name('wtf'), 0, 'unknown cipher name';
is gcry_cipher_map_name('aes'), 7, 'known cipher name';
is gcry_md_map_name('wtf'), 0, 'unknown digest name';
is gcry_md_map_name('sha256'), 8, 'known digest name';

done-testing;


