use v6;
use Test;
use Crypt::GCrypt;

nok Crypt::GCrypt::cipher_algo_available('wtf'), 'unknown cipher name is not available';
ok Crypt::GCrypt::cipher_algo_available('aes'), 'unknown cipher name is availale';

nok Crypt::GCrypt::digest_algo_available('wtf'), 'unknown cipher name is not available';
ok Crypt::GCrypt::digest_algo_available('sha256'), 'unknown cipher name is available';

done-testing;


