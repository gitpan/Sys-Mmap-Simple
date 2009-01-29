package Sys::Mmap::Simple;

# This software is copyright (c) 2008, 2009 by Leon Timmermans <leont@cpan.org>.
#
# This is free software; you can redistribute it and/or modify it under
# the same terms as perl itself.

use 5.007003;
use strict;
use warnings;

use base qw/Exporter DynaLoader/;
use Symbol qw/qualify_to_ref/;
use Carp qw/croak/;

our $VERSION = '0.09';

our (@EXPORT_OK, %EXPORT_TAGS);

bootstrap Sys::Mmap::Simple $VERSION;

my %writable_for = (
	'<'  => 0,
	'+<' => 1,
	'>'  => 1,
	'+>' => 1,
);

my %export_data = (
	MAP   => [qw/map_handle map_file map_anonymous unmap/],
	EXTRA => [qw/remap sync pin unpin/],
	LOCK  => [qw/locked condition_wait condition_signal condition_broadcast/],
);

while (my ($category, $functions) = each %export_data) {
	for my $function (grep { defined &{$_} } @{$functions}) {
		push @EXPORT_OK, $function;
		push @{ $EXPORT_TAGS{$category} }, $function;
	}
}

sub map_handle(\$*@) {
	my ($var_ref, $glob, $mode, $offset, $length) = @_;
	my $fh = qualify_to_ref($glob, caller);
	$offset ||= 0;
	$length ||= (-s $fh) - $offset;
	return _mmap_wrapper($var_ref, $length, $writable_for{ $mode || '<' }, fileno $fh, $offset);
}

sub map_file(\$@) {
	my ($var_ref, $filename, $mode, $offset, $length) = @_;
	$mode   ||= '<';
	$offset ||= 0;
	open my $fh, $mode, $filename or croak "Couldn't open file $filename: $!";
	$length ||= (-s $fh) - $offset;
	my $ret = _mmap_wrapper($var_ref, $length, $writable_for{$mode}, fileno $fh, $offset);
	close $fh or croak "Couldn't close $filename: $!";
	return $ret;
}

sub _mmap_wrapper {
	my $ret;
	eval { $ret = _mmap_impl(@_) };
	if ($@) {
		$@ =~ s/\n$//mx;
		croak $@;
	}
	return $ret;
}

1;

__END__

=head1 NAME

Sys::Mmap::Simple - Memory mapping made simple and safe.

=head1 VERSION

Version 0.09

=head1 SYNOPSIS

 use Sys::Mmap::Simple 'map_file';
 
 map_file my $mmap, $filename;
 if ($mmap eq "foobar") {
     $mmap =~ s/bar/quz/g;
 }

=head1 DESCRIPTION

Sys::Mmap::Simple maps files or anonymous memory into perl variables.

=head2 Advantages of memory mapping

=over 4

=item * Unlike normal perl variables, mapped memory is shared between threads or forked processes.

=item * It is an efficient way to slurp an entire file. Unlike for example L<File::Slurp>, this module returns almost immediately, loading the pages lazily on access. This means you only 'pay' for the parts of the file you actually use.

=item * Perl normally never returns memory to the system while running, mapped memory can be returned.

=back

=head2 Advantages of this module over other similar modules

=over 4

=item * Safety and Speed

This module is safe yet fast. Alternatives are either fast but can cause segfaults or loose the mapping when not used correctly, or are safe but rather slow. Sys::Mmap::Simple is as fast as a normal string yet safe.

=item * Simplicity

It offers a more simple interface targeted at common usage patterns

=over 4

=item * Files are mapped into a variable that can be read just like any other variable, and it can be written to using standard Perl techniques such as regexps and C<substr>.

=item * Files can be mapped using a set of simple functions. No weird constants or 6 argument functions.

=item * It will automatically unmap the file when the scalar gets destroyed. This works correctly even in multithreaded programs.

=back

=item * Portability

Sys::Mmap::Simple supports both Unix and Windows.

=item * Thread synchronization

It has built-in support for thread synchronization. 

=back

=head1 FUNCTIONS

=head2 Mapping

The following functions for mapping a variable are available for exportation. They all take an lvalue as their first argument.

=over 4

=item * map_handle $lvalue, *handle, $mode = '<', $offset = 0, $length = -s(*handle) - $offset

Use a filehandle to mmap into an lvalue. *handle may be a bareword, constant, scalar expression, typeglob, or a reference to a typeglob. $mode uses the same format as C<open> does. $offset and $length are byte positions in the file.

=item * map_file $lvalue, $filename, $mode = '<', $length = -s($filename) - $offset

Open a file and mmap it into an lvalue. $offset and $length are byte positions in the file.

=item * map_anonymous $lvalue, $length

Map an anonymous piece of memory.

=item * sync $lvalue, $synchronous = 1

Flush changes made to the memory map back to disk. Mappings are always flushed when unmapped, so this is usually not necessary. If $synchronous is true and your operating system supports it, the flushing will be done synchronously.

=item * remap $lvalue, $new_size

Try to remap $lvalue to a new size. It may fail if there is not sufficient space to expand a mapping at its current location. This call is linux specific and currently not supported or even defined on other systems.

=item * unmap $lvalue

Unmap a variable. Note that normally this is not necessary, but it is included for completeness.

=item * pin $lvalue

Disable paging for this map, thus locking it in physical memory. Depending on your operating system there may be limits on pinning.

=item * unpin $lvalue

Unlock the map from physical memory.

=back

=head2 Locking

These locking functions provide locking for threads for the mapped region. The mapped region has an internal lock and condition variable. The condition variable functions can only be used inside a locked block. If your perl has been compiled without thread support the condition functions will not be available, and C<locked> will execute its block without locking.

=over 4

=item * locked { block } $lvalue

Perform an action while keeping a thread lock on the map. The map is accessible as C<$_>. It will return whatever its block returns.

=item * condition_wait { block }

Wait for block to become true. After every failed try, wait for a signal. It returns the value returned by the block.

=item * condition_signal

This will signal to one listener that the map is available.

=item * condition_broadcast

This will signal to all listeners that the map is available.

=back

=head1 EXPORTS

All previously mentioned functions are availible for exportation, but none are exported by default. Some functions may not be availible on your OS or your version of perl as specified above. A number of tags are defined to make importation easier.

=over 4

=item * MAP

map_handle, map_file, map_anonymous, unmap

=item * EXTRA

remap, sync, pin, unpin

=item * LOCK

locked, condition_wait, condition_signal, condition_broadcast

=back

=head1 DIAGNOSTICS

If you C<use warnings>, this module will give warnings if the variable is improperly used (anything that changes its size). This can be turned off lexically by using C<no warnings 'substr'>.

If an error occurs in any of these functions, an exception will be thrown. In particular; trying to sync, remap, unmap, pin, unpin or lock a variable that hasn't been mapped will cause an exception to be thrown.

=head1 DEPENDENCIES

This module does not have any dependencies on other modules.

=head1 BUGS AND LIMITATIONS

This is an early release. Bugs are likely. Bug reports are welcome.

Please report any bugs or feature requests to C<bug-sys-mmap-simple at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Sys-Mmap-Simple>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SEE ALSO

=over 4

=item * L<Sys::Mmap>, the original Perl mmap module

=item * L<IPC::Mmap>, another mmap module

=item * L<mmap(2)>. your mmap man page

=item * CreateFileMapping at MSDN: L<http://msdn.microsoft.com/en-us/library/aa366537(VS.85).aspx>

=back

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

Copyright 2008, 2009 Leon Timmermans, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as perl itself.
