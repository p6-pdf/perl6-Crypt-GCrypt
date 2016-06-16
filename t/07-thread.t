use v6;
use Crypt::GCrypt::Cipher;
use Test;

my @algos = <aes twofish blowfish arcfour cast5 des serpent seed>;
my @available-algos = @algos.grep: { Crypt::GCrypt::Cipher.algo-available($_) };

my $str = 'Four Score and Seven years ago, our fore-monkeys created a great blah blah blah';
my $key = 'monkeymonkeymonkey';

sub nonthreadtest($algo) {
  my $enc = Crypt::GCrypt::Cipher.new(
      type => 'cipher',
      algorithm => $algo,
      #mode => 'cbc',
      #padding => 'null'
  );
  $enc.start('encrypting');
  $enc.setkey($key, $enc.keylen);

  my $dec = Crypt::GCrypt::Cipher.new(
      type => 'cipher',
      algorithm => $algo,
      #mode => 'cbc',
      #padding => 'null'
  );
  $dec.start('decrypting');
  $dec.setkey($key, $enc.keylen);

  my $buf = $enc.encrypt($str.encode("latin-1"));
  my $out = Buf.new: $dec.decrypt($buf);
  $buf = $enc.finish();
  $out.append: $dec.decrypt($buf);
  $out.append: $dec.finish();
  my $outstr = $out.decode("latin-1");
  warn sprintf("Non-threaded: Failed to match output with algorithm '%s'\n", $algo) if ($str ne $outstr);
  return ($str eq $outstr);
}

sub producer-thread(Channel $q, Str $algo) {

    warn "producing $algo";
  my $enc = Crypt::GCrypt::Cipher.new(
                               type => 'cipher',
                               algorithm => $algo,
                               #mode => 'cbc',
                               #padding => 'null'
                              );
  $enc.start('encrypting');
  $enc.setkey($key, $enc.keylen);
  $q.send($enc.encrypt($str));
  $q.send($enc.finish());
  $q.send(Any);
  return $q;
}

sub consumer-thread(Channel $q, Str $algo) {

    warn "consuming $algo";
  my $dec = Crypt::GCrypt::Cipher.new(
                               type => 'cipher',
                               algorithm => $algo,
                               #mode => 'cbc',
                               #padding => 'null'
                              );
  $dec.start('decrypting');
  $dec.setkey($key, $dec.keylen);
  my $out = Buf.new;
  my $buf;
  repeat {
      $buf = $q.receive;
      warn :receive{ :$buf }.perl;
      $out.append($dec.decrypt($buf))
          if (defined $buf);
  } while defined $buf;
  $out.append: $dec.finish();
  $out.decode("latin-1");
}

my $ = Channel.new;

sub testalgo($algo) {
    ok nonthreadtest($algo), $algo;

    my $queue = Channel.new;

    # create in scalar context so that the result is the returned scalar:
    producer-thread($queue, $algo);
    my $outstr = consumer-thread($queue, $algo);
}
my @results = await ('aes' xx 5).map: { start { $_ => testalgo($_) } };
##my @results = await @available-algos.map: { start { $_ => testalgo($_) } };
warn @results.perl;

done-testing;
