use strict;
use warnings;
use Module::Build;

exit 0 unless Module::Build->y_n('Are you sure you want to install this deprecated module? (please install File::Map instead)', 'no');

my $builder = Module::Build->new(
    module_name         => 'Sys::Mmap::Simple',
    license             => 'perl',
    dist_author         => 'Leon Timmermans <leont@cpan.org>',
    version             => 0.14,
    build_requires => {
        'Test::More' => 0,
    },
	requires            => {
		perl            => 5.007003,
		'File::Map'     => 0.13,
		Exporter        => 5.57,
		'Sub::Prototype' => 0.02,
	},
    add_to_cleanup      => [ 'Sys-Mmap-Simple-*' ],
    create_makefile_pl  => 'traditional',
	sign                => 1,
);

$builder->create_build_script();
