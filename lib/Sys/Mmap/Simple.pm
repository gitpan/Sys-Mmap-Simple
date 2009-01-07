package Sys::Mmap::Simple;

use 5.007003;
use strict;
use warnings;

use base   qw/Exporter DynaLoader/;
use Symbol qw/qualify_to_ref/;
use Carp   qw/croak/;

BEGIN {
	our $VERSION = '0.03_2';

	our @EXPORT_OK = qw/map_handle map_file map_anonymous sync locked unmap/;

	our %EXPORT_TAGS = (
		MAP       => [qw/map_handle map_file map_anonymous unmap/],
	);

	bootstrap Sys::Mmap::Simple $VERSION;

	if (defined &condition_wait) {
		my @cond_funcs = qw/condition_wait condition_signal condition_broadcast/;
		push @EXPORT_OK, @cond_funcs;
		$EXPORT_TAGS{CONDITION} = \@cond_funcs;
	}
}

sub map_handle(\$*@) {
	my ($var_ref, $glob, $writable) = @_;
	my $fh = qualify_to_ref($glob, caller);
	return _mmap_wrapper($var_ref, -s $fh, defined $writable ? $writable : 0, fileno $fh);
}

sub map_file(\$@) {
	my ($var_ref, $filename, $writable) = @_;
	my $mode = $writable ? '+<' : '<';
	open my $fh, $mode, $filename or croak "Couldn't open file $filename: $!";
	my $ret = _mmap_wrapper($var_ref, -s $fh, defined $writable ? $writable : 0, fileno $fh);
	close $fh or croak "Couldn't close $filename: $!";
	return $ret;
}

sub _mmap_wrapper {
	my $ret;
	eval { $ret = _mmap_impl(@_) };
	if ($@) {
		$@ =~ s/\n$//m;
		croak $@;
	}
	return $ret;
}

1;

__END__

=head1 NAME

Sys::Mmap::Simple - Memory mapping made simple and safe.

=head1 VERSION

Version 0.01

=head1 SYNOPSIS

 use Sys::Mmap::Simple 'map_file';
 
 map_file(my $mmap, $filename);
 if ($mmap eq "foobar") {
     $mmap =~ s/bar/quz/g;
 }

=head1 DESCRIPTION

This module maps files to Perl variables. There are a few differences between this module and L<Sys::Mmap>.

=over 4

=item * It offers a more simple interface. It always maps the whole file, and always does shared mapping. This seems to be what people want in 95% of all cases.

=item * This module is safe yet fast. Sys::Mmap offers two interfaces, one is fast, but can lose its cou segfault if not used correctly. The other is safe, but reportedly 10 times slower. Sys::Mmap::Simple is fast (as long as it is used properly) and safe.

=item * It will automatically unmap the file when the scalar gets destroyed.

=item * It has built-in support for thread synchronization. 

=back

=head1 FUNCTIONS

=head2 MAPPING

The following functions for mapping a variable are availible for exportation. They all take an lvalue as their first argument.

=head3 map_handle $variable, *handle, $writable = 0

Use a filehandle to mmap into a variable. *handle may be filehandle or a reference to a filehandle.

=head3 map_file $variable, $filename, $writable = 0

Open a file and mmap it into a variable.

=head3 map_anonymous $variable, $length

Map an anonymous piece of memory.

=head3 sync $variable

Flush changes made to the memory map back to disk. Mappings are always synced when unmapped, so this is usually not necessary. 

=head3 unmap $variable

Unmap a variable. Note that normally this is not necessary, but it is included for completeness.

=head2 LOCKING

These locking functions provide thread based locking for the mapped region. The mapped region has an internal lock and condition variable. The condional functions can only be used in a locked block. If your perl has been compiled without thread support the condition functions will not be availible, and C<locked> will execute its block without locking.

=head3 locked { block } $variable

Perform an action while keeping a thread lock on the map. The map is accessable as C<$_>. It will return whatever its block returns.

=head3 condition_wait { block }

While the block is false, wait for signals.

=head3 condition_signal

This will signal to one listener that the map is availible.

=head3 condition_broadcast

This will signal to all listeners that the map is availible.

=head1 DIAGNOSTICS

If you C<use warnings>, this module will give warnings if the variable is improperly used (anything that changes its size). This can be turned off lexically by using C<no warnings 'substr'>.

Trying to sync or unmap a variable that hasn't been mapped will result in an exception.

=head1 BUGS AND LIMITATIONS

This is an early release. Bugs are likely. Bug reports are welcome.

Please report any bugs or feature requests to C<bug-sys-mmap-simple at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Sys-Mmap-Simple>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 AUTHOR

Leon Timmermans, C<< <leont at cpan.org> >>

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Sys::Mmap::Simple


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Sys-Mmap-Simple>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Sys-Mmap-Simple>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Sys-Mmap-Simple>

=item * Search CPAN

L<http://search.cpan.org/dist/Sys-Mmap-Simple>

=back

=head1 COPYRIGHT AND LICENSE

Copyright 2008 Leon Timmermans, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.
