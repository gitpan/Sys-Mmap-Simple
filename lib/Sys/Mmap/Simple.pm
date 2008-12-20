package Sys::Mmap::Simple;

use 5.007003;
use strict;
use warnings;

use base   qw/Exporter DynaLoader/;
use Symbol qw/qualify_to_ref/;
use Carp   qw/croak/;

our $VERSION = '0.02';

our @EXPORT_OK = qw/map_handle map_file map_anonymous sync locked unmap/;

bootstrap Sys::Mmap::Simple $VERSION;

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

=item * This module is safe yet fast. Sys::Mmap offers two interfaces, one is fast, but can segfault if not used correctly. The other is safe, but reportedly 10 times slower. Sys::Mmap::Simple is fast (as long as it is used properly) and safe.

=item * It will automatically unmap the file when the scalar gets destroyed.

=back

=head1 FUNCTIONS

The following functions are defined and availible for exportation.

=head2 map_handle $variable, *handle, $writable = 0

Use a filehandle to mmap into a variable. $variable must be an lvalue. *handle may be filehandle or a reference to a filehandle.

=head2 map_file $variable, $filename, $writable = 0

Open a file and mmap it into a variable. $variable must be an lvalue.

=head2 map_anonymous $variable, $length

Map an anonymous piece of memory.

=head2 sync $variable

Flush changes made to the memory map back to disk.

=head2 locked { block } $variable

Perform an action while keeping a thread lock on the map. The map is accessable as C<$_>. This is only useful when using threads.

=head2 unmap $scalar

Unmap a variable. Note that normally this is not necessary, but it is included for completeness.

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
