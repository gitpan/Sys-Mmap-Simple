#include <sys/mman.h>
#include <unistd.h>

#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#if defined USE_ITHREADS && defined MGf_DUP
#define MMAP_THREADED
#endif

#define MMAP_MAGIC_NUMBER 0x4c54

struct mmap_info {
	void* address;
	U32 length;
#ifdef MMAP_THREADED
	perl_mutex mutex;
	int count;
#endif
};

static int mmap_write(pTHX_ SV* var, MAGIC* magic) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
	if (SvTYPE(var) < SVt_PV)
		sv_upgrade(var, SVt_PV);
	if (SvPVX(var) != info->address) {
		if (ckWARN(WARN_SUBSTR))
			Perl_warn(aTHX_ "Writing directly to a to an mmaped file is not recommended");

		Copy(SvPVX(var), info->address, MIN(SvLEN(var), info->length), char);
		SvPV_free(var);
		SvPVX(var) = info->address;
		SvLEN(var) = 0;
		SvCUR(var) = info->length;
		SvPOK_only(var);
	}
	return 0;
}

static U32 mmap_length(pTHX_ SV* var, MAGIC* magic) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
	return info->length;
}

static int mmap_clear(pTHX_ SV* var, MAGIC* magic) {
	if (ckWARN(WARN_SUBSTR))
		Perl_warn(aTHX_ "Clearing a memory mapped file?");
	return 0;
}

static int mmap_free(pTHX_ SV* var, MAGIC* magic) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
#ifdef MMAP_THREADED
	MUTEX_LOCK(&info->mutex);
	if (--info->count == 0) {
		if (munmap(info->address, info->length) == -1)
			Perl_croak(aTHX_ "Could not munmap: %s\n", strerror(errno));
		MUTEX_UNLOCK(&info->mutex);
		MUTEX_DESTROY(&info->mutex);
		Safefree(info);
	}
	else {
		if (msync(info->address, info->length, MS_SYNC) == -1)
			Perl_croak(aTHX_ "Could not msync: %s\n", strerror(errno));
		MUTEX_UNLOCK(&info->mutex);
	}
#else 
	if (munmap(info->address, info->length) == -1)
		Perl_croak(aTHX_ "Could not munmap: %s\n", strerror(errno));
	Safefree(info);
#endif
	SvPVX(var) = NULL;
	SvCUR(var) = 0;
	return 0;
}

#ifdef MMAP_THREADED
static int mmap_dup(pTHX_ MAGIC* magic, CLONE_PARAMS* param) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
	MUTEX_LOCK(&info->mutex);
	ASSERT(info->count);
	++info->count;
	MUTEX_UNLOCK(&info->mutex);
	return 0;
}
#define table_tail ,0, mmap_dup, 0
#else
#define table_tail 
#endif

static const MGVTBL mmap_read_table  = { 0, 0,          mmap_length, mmap_clear, mmap_free table_tail };
static const MGVTBL mmap_write_table = { 0, mmap_write, mmap_length, mmap_clear, mmap_free table_tail };

static void mmap_impl(pTHX_ SV* var_ref, size_t length, int writable, int flags, int fd) {
	SV* var = SvRV(var_ref);
	if (SvTYPE(var) > SVt_PVMG && SvTYPE(var) != SVt_PVLV)
		Perl_croak(aTHX_ "Trying to map into a nonscalar!");
	if (SvMAGICAL(var) && mg_find(var, PERL_MAGIC_uvar))
		sv_unmagic(var, PERL_MAGIC_uvar);
	sv_upgrade(var, SVt_PV);
	if (SvPOK(var)) 
		SvPV_free(var);
	
	int prot = writable ? PROT_READ | PROT_WRITE : PROT_READ;
	void* address = mmap(0, length, prot, flags, fd, 0);
	if (address == MAP_FAILED)
		Perl_croak(aTHX_ "Could not mmap: %s\n", strerror(errno));

	struct mmap_info* magical;
	New(0, magical, 1, struct mmap_info);
	magical->address = address;
	magical->length = length;
#ifdef MMAP_THREADED
	MUTEX_INIT(&magical->mutex);
	magical->count = 1;
#endif

	SvPVX(var) = address;
	SvLEN(var) = 0;
	SvCUR(var) = length;
	SvPOK_only(var);

	const MGVTBL* table = writable ? &mmap_write_table : &mmap_read_table;
	MAGIC* magic = sv_magicext(var, NULL, PERL_MAGIC_uvar, table, (const char*) magical, 0);
	magic->mg_private = MMAP_MAGIC_NUMBER;
#ifdef MMAP_THREADED
	magic->mg_flags |= MGf_DUP;
#endif
	if (!writable)
		SvREADONLY_on(var);
}

static MAGIC* check_mmap_magic(pTHX_ SV* var) {
	MAGIC* magic;
	if (!SvMAGICAL(var) || (magic = mg_find(var, PERL_MAGIC_uvar)) == NULL ||  magic->mg_private != MMAP_MAGIC_NUMBER)
		Perl_croak(aTHX_ "This variable is not mmaped\n");
	return magic;
}

MODULE = Sys::Mmap::Simple				PACKAGE = Sys::Mmap::Simple

PROTOTYPES: DISABLED

SV*
_mmap_impl(var_ref, length, writable, fd)
	SV* var_ref;
	int fd;
	size_t length;
	int writable;
	CODE:
		ST(0) = &PL_sv_undef;
		mmap_impl(aTHX_ var_ref, length, writable, MAP_SHARED, fd);
		ST(0) = &PL_sv_yes;

SV*
map_anonymous(var_ref, length)
	SV* var_ref;
	size_t length;
	PROTOTYPE: \$@
	CODE:
		ST(0) = &PL_sv_undef;
		if (length == 0)
			Perl_croak(aTHX_ "No length specified for anonymous map\n");
		mmap_impl(aTHX_ var_ref, length, 1, MAP_SHARED | MAP_ANONYMOUS, -1);
		ST(0) = &PL_sv_yes;

SV*
sync(var_ref)
	SV* var_ref;
	PROTOTYPE: \$
	CODE:
		ST(0) = &PL_sv_undef;
		SV* var = SvRV(var_ref);
		MAGIC* magical = check_mmap_magic(aTHX_ var);
		struct mmap_info* info = (struct mmap_info*) magical->mg_ptr;
		if (msync(info->address, info->length, MS_SYNC) == -1)
			Perl_croak(aTHX_ "Could not msync: %s\n", strerror(errno));
		ST(0) = &PL_sv_yes;

SV*
unmap(var_ref)
	SV* var_ref;
	PROTOTYPE: \$
	CODE: 
		ST(0) = &PL_sv_undef;
		SV* var = SvRV(var_ref);
		check_mmap_magic(aTHX_ var);
		sv_unmagic(var, PERL_MAGIC_uvar);
		ST(0) = &PL_sv_yes;

void
_error()
	CODE:
		Perl_croak(aTHX_ "Error!\n");
