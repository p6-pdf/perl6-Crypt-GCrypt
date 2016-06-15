use v6;
use Test;
use Crypt::GCrypt::Digest;

ok Crypt::GCrypt::Digest.algo-available('sha256'), 'known digest name is available';
nok Crypt::GCrypt::Digest.algo-available('wtf'), 'unknown digest name is not available';

ok 'sha256' ~~  Crypt::GCrypt::Digest::DigestName, 'DigestName';
ok 'wtf' !~~  Crypt::GCrypt::Digest::DigestName, 'not DigestName';

done-testing;
