package Sys::Mmap::Simple;

use strict;
use warnings;

our $VERSION = 0.14;

use File::Map 0.13 qw/:constants lock_map/;
use Exporter 5.57 'import';
use Symbol 'qualify_to_ref';
use Sub::Prototype 0.02;

our @EXPORT_OK = grep !/lock_map/, @File::Map::EXPORT_OK, 'locked';
our %EXPORT_TAGS = %File::Map::EXPORT_TAGS;
@{ $EXPORT_TAGS{lock} } = qw/locked/;

sub locked(&\$) {
	my ($block, $var_ref) = @_;
	for (${$var_ref}) {
		lock_map $_;
		return $block->();
	}
}

sub map_handle(\$*@) {
	my @args = @_;
	$args[1] = qualify_to_ref($args[1]);
	&File::Map::map_handle(@args);
	return 1;
}

for my $subname (qw/map_file map_anonymous sys_map unmap sync pin unpin advise/, ( defined &File::Map::remap ? 'remap' : ())) {
	no strict 'refs';
	*{$subname} = sub {
		&{"File::Map::$subname"}(@_);
		return 1;
	};
	set_prototype(\&{$subname}, prototype \&{"File::Map::$subname"});
}

if (defined &File::Map::wait_until) {
	*wait_until = sub(&) {
		my $block = shift;
		return File::Map::wait_until(\&$block, $_);
	};
	*notify = sub() {
		File::Map::notify $_;
	};
	*broadcast = sub() {
		File::Map::broadcast $_;
	};
	
	for my $array($EXPORT_TAGS{lock}, \@EXPORT_OK) {
		push @{$array}, qw/wait_until notify broadcast/;
	}
}

1;

__END__

=head1 NAME

Sys::Mmap::Simple - Memory mapping made simple and safe.

=head1 VERSION

Version 0.14

=head1 SYNOPSIS

 use Sys::Mmap::Simple ':MAP';
 
 map_file my $mmap, $filename;
 if ($mmap ne "foobar") {
     $mmap =~ s/bar/quz/g;
 }

=head1 DESCRIPTION

B<This module is deprecated in favor of File::Map, its use is discouraged>. It's nothing more than a thin compatibility layer.

=head1 FUNCTIONS

=head2 Mapping

The following functions for mapping a variable are available for exportation. They all take an lvalue as their first argument, except page_size.

=over 4

=item * map_handle $lvalue, *filehandle, $mode = '<', $offset = 0, $length = -s(*handle) - $offset

Use a filehandle to mmap into an lvalue. *filehandle may be a bareword, constant, scalar expression, typeglob, or a reference to a typeglob. $mode uses the same format as C<open> does. $offset and $length are byte positions in the file, and default to mapping the whole file.

=item * map_file $lvalue, $filename, $mode = '<', $offset = 0, $length = -s($filename) - $offset

Open a file and mmap it into an lvalue. Other than $filename, all arguments work as in map_handle.

=item * map_anonymous $lvalue, $length

Map an anonymous piece of memory.

=item * sys_map $lvalue, $length, $protection, $flags, *filehandle, $offset = 0

Low level map operation. It accepts the same constants as mmap does (except its first argument obviously). If you don't know how mmap works you probably shouldn't be using this.

=item * sync $lvalue, $synchronous = 1

Flush changes made to the memory map back to disk. Mappings are always flushed when unmapped, so this is usually not necessary. If $synchronous is true and your operating system supports it, the flushing will be done synchronously.

=item * remap $lvalue, $new_size

Try to remap $lvalue to a new size. It may fail if there is not sufficient space to expand a mapping at its current location. This call is linux specific and currently not supported on other systems.

=item * unmap $lvalue

Unmap a variable. Note that normally this is not necessary, but it is included for completeness.

=item * pin $lvalue

Disable paging for this map, thus locking it in physical memory. Depending on your operating system there may be limits on pinning.

=item * unpin $lvalue

Unlock the map from physical memory.

=item * advise $lvalue, $advice

Advise a certain memory usage pattern. This is not implemented on all operating systems, and may be a no-op. $advice is a string with one of the following values.

=over 2

=item * normal 

Specifies that the application has no advice to give on its behavior with respect to the mapped variable. It is the default characteristic if no advice is given.

=item * random

Specifies that the application expects to access the mapped variable in a random order.

=item * sequential

Specifies that the application expects to access the mapped variable sequentially from start to end.

=item * willneed

Specifies that the application expects to access the mapped variable in the near future.

=item * dontneed

Specifies that the application expects that it will not access the mapped variable in the near future.

=back

=back

=head2 Locking

These locking functions provide locking for threads for the mapped region. The mapped region has an internal lock and condition variable. The condition variable functions(C<wait_until>, C<notify>, C<broadcast>) can only be used inside a locked block. If your perl has been compiled without thread support the condition functions will not be available, and C<locked> will execute its block without locking.

=over 4

=item * locked { block } $lvalue

Perform an action while keeping a thread lock on the map. The map is accessible as C<$_>. It will return whatever its block returns.

=item * wait_until { block }

Wait for block to become true. After every failed try, wait for a signal. It returns the value returned by the block.

=item * notify

This will signal to one listener that the map is available.

=item * broadcast

This will signal to all listeners that the map is available.

=back

=head2 CONSTANTS

=over 4

=item PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC, MAP_ANONYMOUS, MAP_SHARED, MAP_PRIVATE, MAP_ANON, MAP_FILE

These constants are used for sys_map. If you think you need them your mmap manpage will explain them, but in most cases you can skip sys_map altogether.

=back

=head1 EXPORTS

All previously mentioned functions are available for exportation, but none are exported by default. Some functions may not be available on your OS or your version of perl as specified above. A number of tags are defined to make importation easier.

=over 4

=item * map

map_handle, map_file, map_anonymous, sys_map, unmap

=item * extra

remap, sync, pin, unpin, advise

=item * lock

locked, wait_until, notify, broadcast

=item * constants

PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC, MAP_ANONYMOUS, MAP_SHARED, MAP_PRIVATE, MAP_ANON, MAP_FILE

=back

=head1 DIAGNOSTICS

If you C<use warnings>, this module will give warnings if the variable is improperly used (anything that changes its size). This can be turned off lexically by using C<no warnings 'substr'>.

If an error occurs in any of these functions, an exception will be thrown. In particular; trying to C<sync>, C<remap>, C<unmap>, C<pin>, C<unpin>, C<advise> or do C<locked> a variable that hasn't been mapped will cause an exception to be thrown.

=head1 DEPENDENCIES

This module does not have any dependencies on non-standard modules.

=head1 PITFALLS

You probably don't want to use C<E<gt>> as a mode. This does not give you reading permissions on many architectures, resulting in segmentation faults (more confusingly, it will work on some others).

=head1 BUGS AND LIMITATIONS

As any piece of software, bugs are likely to exist here. Bug reports are welcome.

Please report any bugs or feature requests to C<bug-sys-mmap-simple at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Sys-Mmap-Simple>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SEE ALSO

=over 4

=item * L<File::Map>, the successor of this module

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
