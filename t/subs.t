use v6;
use Test;
use Crypt::GCrypt;

ok Crypt::GCrypt::cipher_algo_available('aes'), 'unknown cipher name is availale';
nok Crypt::GCrypt::cipher_algo_available('wtf'), 'unknown cipher name is not available';

ok 'aes' ~~  Crypt::GCrypt::CipherName, 'CipherName';
ok 'wtf' !~~  Crypt::GCrypt::CipherName, 'not CipherName';

ok Crypt::GCrypt::digest_algo_available('sha256'), 'unknown cipher name is available';
nok Crypt::GCrypt::digest_algo_available('wtf'), 'unknown cipher name is not available';

ok 'sha256' ~~  Crypt::GCrypt::DigestName, 'DigestName';
ok 'wtf' !~~  Crypt::GCrypt::DigestName, 'not DigestName';

done-testing;


