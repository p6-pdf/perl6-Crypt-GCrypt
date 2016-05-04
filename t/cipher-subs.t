use v6;
use Test;
use Crypt::GCrypt::Cipher;

ok Crypt::GCrypt::Cipher::cipher_algo_available('aes'), 'unknown cipher name is availale';
nok Crypt::GCrypt::Cipher::cipher_algo_available('wtf'), 'unknown cipher name is not available';

ok 'aes' ~~  Crypt::GCrypt::Cipher::CipherName, 'CipherName';
ok 'wtf' !~~  Crypt::GCrypt::Cipher::CipherName, 'not CipherName';

done-testing;


