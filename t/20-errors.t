#!perl

use strict;
use warnings;
use Sys::Mmap::Simple qw/:MAP locked sync/;
use IO::Handle;
use Test::More tests => 12;
use Test::Warn;
use Test::Exception;

open my $self, '<', $0 or die "Couldn't open self: $!";
my $slurped = do { local $/; <$self> };

open my $copy, "+<", undef or die "Couldn't create tempfile: $!";
$copy->autoflush(1);
print $copy $slurped;

ok(map_handle(my $mmaped, $copy, '+>'), "map succeeded");

warnings_like { $mmaped = reverse $mmaped; } [ qr/^Writing directly to a to a memory mapped file is not recommended at /, qr/^Truncating new value to size of the memory map at /], 'reversing should give a warning';

is($mmaped, scalar reverse($slurped), "mmap is reversed");

warning_is { $mmaped = $mmaped } undef, "no warnings on self-assignment";

dies_ok { map_file my $var, 'some-nonexistant-file' } 'Can\'t map non-existant files as readonly';

warnings_like { $mmaped =~ s/(.)/$1$1/ } [ qr/^Writing directly to a to a memory mapped file is not recommended at /, qr/^Truncating new value to size of the memory map at /], 'Trying to make it longer gives warnings';

warning_like { $slurped =~ tr/r/t/; } undef, 'translation shouldn\'t cause warnings';

throws_ok { sync my $foo } qr/^Could not sync: this variable is not memory mapped at /, 'Can\'t sync normal variables';

throws_ok { unmap my $foo } qr/^Could not unmap: this variable is not memory mapped at /, 'Can\'t unmap normal variables';

throws_ok { locked {} my $foo } qr/^Could not do locked: this variable is not memory mapped at /, 'Can\'t lock normal variables';

throws_ok { map_anonymous my $foo, 0 } qr/^Zero length specified for anonymous map at /, 'Have to provide a length for anonymous maps';

throws_ok { &map_anonymous("foo", 1000) } qr/^Invalid argument! at /, 'Can\'t ignore prototypes';
