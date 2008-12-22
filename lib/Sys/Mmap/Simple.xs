#include <sys/mman.h>
#include <unistd.h>

#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#define MMAP_MAGIC_NUMBER 0x4c54

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

struct mmap_info {
	void* address;
	U32 length;
#ifdef USE_ITHREADS
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
#ifdef USE_ITHREADS
	MUTEX_LOCK(&info->mutex);
	if (--info->count == 0) {
		if (munmap(info->address, info->length) == -1)
			Perl_croak(aTHX_ "Could not munmap: %s", strerror(errno));
		MUTEX_UNLOCK(&info->mutex);
		MUTEX_DESTROY(&info->mutex);
		Safefree(info);
	}
	else {
		if (msync(info->address, info->length, MS_SYNC) == -1)
			Perl_croak(aTHX_ "Could not msync: %s", strerror(errno));
		MUTEX_UNLOCK(&info->mutex);
	}
#else 
	if (munmap(info->address, info->length) == -1)
		Perl_croak(aTHX_ "Could not munmap: %s", strerror(errno));
	Safefree(info);
#endif
	SvPVX(var) = NULL;
	SvCUR(var) = 0;
	return 0;
}

#ifdef USE_ITHREADS

static int mmap_dup(pTHX_ MAGIC* magic, CLONE_PARAMS* param) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
	MUTEX_LOCK(&info->mutex);
	ASSERT(info->count);
	++info->count;
	MUTEX_UNLOCK(&info->mutex);
	return 0;
}
#define TABLE_TAIL ,0, mmap_dup, 0
#define LOCKED(info, command) \
    STMT_START {                            \
		MUTEX_LOCK(&info->mutex);\
		command;\
		MUTEX_UNLOCK(&info->mutex);\
    } STMT_END

#else

#define TABLE_TAIL 
#define LOCKED(info, command) command

#endif

static const MGVTBL mmap_read_table  = { 0, 0,          mmap_length, mmap_clear, mmap_free TABLE_TAIL };
static const MGVTBL mmap_write_table = { 0, mmap_write, mmap_length, mmap_clear, mmap_free TABLE_TAIL };

static void mmap_impl(pTHX_ SV* var_ref, size_t length, int writable, int flags, int fd) {
	SV* var = SvRV(var_ref);
	if (SvTYPE(var) > SVt_PVMG && SvTYPE(var) != SVt_PVLV)
		Perl_croak(aTHX_ "Trying to map into a nonscalar!\n");
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
#ifdef USE_ITHREADS
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
#ifdef USE_ITHREADS
	magic->mg_flags |= MGf_DUP;
#endif
	if (!writable)
		SvREADONLY_on(var);
}

static struct mmap_info* check_mmap_magic(pTHX_ SV* var) {
	MAGIC* magic;
	if (!SvMAGICAL(var) || (magic = mg_find(var, PERL_MAGIC_uvar)) == NULL ||  magic->mg_private != MMAP_MAGIC_NUMBER)
		Perl_croak(aTHX_ "This variable is not mmaped");
	return (struct mmap_info*) magic->mg_ptr;
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
			Perl_croak(aTHX_ "No length specified for anonymous map");
		mmap_impl(aTHX_ var_ref, length, 1, MAP_SHARED | MAP_ANONYMOUS, -1);
		ST(0) = &PL_sv_yes;

SV*
sync(var_ref)
	SV* var_ref;
	PROTOTYPE: \$
	CODE:
		ST(0) = &PL_sv_undef;
		SV* var = SvRV(var_ref);
		struct mmap_info* info = check_mmap_magic(aTHX_ var);
		if (msync(info->address, info->length, MS_SYNC) == -1)
			Perl_croak(aTHX_ "Could not msync: %s", strerror(errno));
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
locked(code, var_ref)
	SV* code;
	SV* var_ref;
	PROTOTYPE: &\$
	PPCODE:
		SV* var = SvRV(var_ref);
		struct mmap_info* info = check_mmap_magic(aTHX_ var);
		int count;
		SAVESPTR(DEFSV);
		DEFSV = var;
		PUSHMARK(SP);
		LOCKED(info, count = call_sv(code, GIMME_V | G_EVAL));
		if (SvTRUE(ERRSV))
			Perl_croak(aTHX_ NULL);
		XSRETURN(count);

