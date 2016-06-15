use v6;
use Test;
use Crypt::GCrypt::Cipher;

ok Crypt::GCrypt::Cipher.algo-available('aes'), 'known cipher name is available';
nok Crypt::GCrypt::Cipher.algo-available('wtf'), 'unknown cipher name is not available';

ok 'aes' ~~  Crypt::GCrypt::Cipher::CipherName, 'CipherName';
ok 'wtf' !~~  Crypt::GCrypt::Cipher::CipherName, 'not CipherName';

done-testing;


