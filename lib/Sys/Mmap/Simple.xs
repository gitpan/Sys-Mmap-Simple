/*
 * This software is copyright (c) 2008, 2009 by Leon Timmermans <leont@cpan.org>.
 *
 * This is free software; you can redistribute it and/or modify it under
 * the same terms as perl itself.
 *
 */

#include <assert.h>
#ifdef WIN32
#include <windows.h>
#include <io.h>
#define MAP_ANONYMOUS 1
#else
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#ifndef SvPV_free
#define SvPV_free(arg) sv_setpvn_mg(arg, NULL, 0);
#endif

#define MMAP_MAGIC_NUMBER 0x4c54

struct mmap_info {
	void* real_address;
	void* fake_address;
	size_t real_length;
	size_t fake_length;
#ifdef USE_ITHREADS
	perl_mutex count_mutex;
	perl_mutex data_mutex;
	perl_cond cond;
	int count;
#endif
};

#ifdef WIN32

static void croak_sys(pTHX_ const char* format) {
	DWORD last_error = GetLastError(); 
	char buffer[128];

	DWORD format_flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
	int length = FormatMessage(format_flags, NULL, last_error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)buffer, sizeof buffer, NULL);
	if (message[length - 2] == '\r')
		message[length - 2] =  '\0';

	Perl_croak(aTHX_ format, message);
}

static DWORD page_size() {
	static DWORD pagesize = 0;
	if (pagesize == 0) {
		SYSTEM_INFO info;
		GetSystemInfo(&info);
		pagesize = info.dwPageSize;
	}
	return pagesize;
}

#define munmap(address, length) ( UnmapViewOfFile(address) ? 0 : -1 )
#define msync(address, length, flags) ( FlushViewOfFile(address, length) ? 0 : -1 ) 
#define mlock(address, length) ( VirtualLock(address, length) ? 0 : -1 )
#define munlock(address, length) ( VirtualUnlock(address, length) ? 0 : -1 )

#else

static void croak_sys(pTHX_ const char* format) {
	char buffer[128];
	strerror_r(errno, buffer, sizeof buffer);
	Perl_croak(aTHX_ format, buffer);
}

static size_t page_size() {
	static size_t pagesize = 0;
	if (pagesize == 0) {
		pagesize = sysconf(_SC_PAGESIZE);
	}
	return pagesize;
}
#endif

static int mmap_write(pTHX_ SV* var, MAGIC* magic) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
	if (SvTYPE(var) < SVt_PV)
		sv_upgrade(var, SVt_PV);
	if (SvPVX(var) != info->fake_address) {
		if (ckWARN(WARN_SUBSTR)) {
			Perl_warn(aTHX_ "Writing directly to a to a memory mapped file is not recommended");
			if (SvLEN(var) > info->fake_length)
				Perl_warn(aTHX_ "Truncating new value to size of the memory map");
		}

		Copy(SvPVX(var), info->fake_address, MIN(SvLEN(var), info->fake_length), char);
		SvPV_free(var);
		SvPVX(var) = info->fake_address;
		SvLEN(var) = 0;
		SvCUR(var) = info->fake_length;
		SvPOK_only(var);
	}
	return 0;
}

static U32 mmap_length(pTHX_ SV* var, MAGIC* magic) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
	return info->fake_length;
}

static int mmap_clear(pTHX_ SV* var, MAGIC* magic) {
	if (ckWARN(WARN_SUBSTR))
		Perl_warn(aTHX_ "Clearing a memory mapped file?");
	return 0;
}

static int mmap_free(pTHX_ SV* var, MAGIC* magic) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
	int count;
#ifdef USE_ITHREADS
	MUTEX_LOCK(&info->count_mutex);
	if (--info->count == 0) {
		if (munmap(info->real_address, info->real_length) == -1)
			croak_sys(aTHX_ "Could not munmap: %s");
		COND_DESTROY(&info->cond);
		MUTEX_DESTROY(&info->data_mutex);
		MUTEX_UNLOCK(&info->count_mutex);
		MUTEX_DESTROY(&info->count_mutex);
		Safefree(info);
	}
	else {
		if (msync(info->real_address, info->real_length, MS_ASYNC) == -1)
			croak_sys(aTHX_ "Could not msync: %s");
		MUTEX_UNLOCK(&info->count_mutex);
	}
#else
	if (munmap(info->real_address, info->real_length) == -1)
		croak_sys(aTHX_ "Could not munmap: %s");
	Safefree(info);
#endif 
	SvPVX(var) = NULL;
	SvCUR(var) = 0;
	return 0;
}

#ifdef USE_ITHREADS
static int mmap_dup(pTHX_ MAGIC* magic, CLONE_PARAMS* param) {
	struct mmap_info* info = (struct mmap_info*) magic->mg_ptr;
	MUTEX_LOCK(&info->count_mutex);
	assert(info->count);
	++info->count;
	MUTEX_UNLOCK(&info->count_mutex);
	return 0;
}
#define TABLE_TAIL ,0, mmap_dup
#else
#define TABLE_TAIL 
#endif

static const MGVTBL mmap_read_table  = { 0, 0,          mmap_length, mmap_clear, mmap_free TABLE_TAIL };
static const MGVTBL mmap_write_table = { 0, mmap_write, mmap_length, mmap_clear, mmap_free TABLE_TAIL };

static void check_new_variable(pTHX_ SV* var) {
	if (SvTYPE(var) > SVt_PVMG && SvTYPE(var) != SVt_PVLV)
		Perl_croak(aTHX_ "Trying to map into a nonscalar!\n");
	if (SvMAGICAL(var) && mg_find(var, PERL_MAGIC_uvar))
		sv_unmagic(var, PERL_MAGIC_uvar);
	if (SvPOK(var)) 
		SvPV_free(var);
	sv_upgrade(var, SVt_PVMG);
}

static void* do_mapping(pTHX_ size_t length, int writable, int flags, int fd, off_t offset) {
	void* address;
#ifdef WIN32
	int prot = writable ? PAGE_READWRITE | SEC_COMMIT : PAGE_READONLY | SEC_COMMIT;
	HANDLE file = flags == MAP_ANONYMOUS ? INVALID_HANDLE_VALUE : _get_osfhandle(fd);
	HANDLE mapping = CreateFileMapping(file, NULL, prot, 0, length, NULL);
	if (mapping == NULL)
		croak_sys(aTHX_ "Could not mmap: %s\n");
	address = MapViewOfFile(mapping, writable ? FILE_MAP_WRITE : FILE_MAP_READ, 0, offset, length);
	CloseHandle(mapping);
	if (address == NULL)
#else
	int prot = writable ? PROT_READ | PROT_WRITE : PROT_READ;
	address = mmap(0, length, prot, flags, fd, offset);
	if (address == MAP_FAILED)
#endif
		croak_sys(aTHX_ "Could not mmap: %s\n");
	return address;
}

static struct mmap_info* initialize_mmap_info(void* address, size_t length, ptrdiff_t correction) {
	struct mmap_info* magical;
	New(0, magical, 1, struct mmap_info);
	magical->real_address = address;
	magical->fake_address = address + correction;
	magical->real_length = length + correction;
	magical->fake_length = length;
#ifdef USE_ITHREADS
	MUTEX_INIT(&magical->count_mutex);
	MUTEX_INIT(&magical->data_mutex);
	COND_INIT(&magical->cond);
	magical->count = 1;
#endif
	return magical;
}

static void set_var(pTHX_ SV* var, void* address, size_t length, ptrdiff_t correction) {
	SvPVX(var) = address + correction;
	SvLEN(var) = 0;
	SvCUR(var) = length;
	SvPOK_only(var);
}

static void add_magic(pTHX_ SV* var, struct mmap_info* magical, int writable) {
	const MGVTBL* table = writable ? &mmap_write_table : &mmap_read_table;
	MAGIC* magic = sv_magicext(var, NULL, PERL_MAGIC_uvar, table, (const char*) magical, 0);
	magic->mg_private = MMAP_MAGIC_NUMBER;
#ifdef USE_ITHREADS
	magic->mg_flags |= MGf_DUP;
#endif
	if (!writable)
		SvREADONLY_on(var);
}

static void mmap_impl(pTHX_ SV* var, size_t length, int writable, int flags, int fd, off_t offset) {
	check_new_variable(aTHX_ var);

	ptrdiff_t correction = offset % page_size();
	void* address = do_mapping(aTHX_ length + correction, writable, flags, fd, offset - correction);

	struct mmap_info* magical = initialize_mmap_info(address, length, correction);
	set_var(aTHX_ var, address, length, correction);
	add_magic(aTHX_ var, magical, writable);
}

static SV* get_var(pTHX_ SV* var_ref) {
	if (!SvROK(var_ref))
		Perl_croak(aTHX_ "Invalid argument!");
	return SvRV(var_ref);
}

static struct mmap_info* get_mmap_magic(pTHX_ SV* var, const char* funcname) {
	MAGIC* magic;
	if (!SvMAGICAL(var) || (magic = mg_find(var, PERL_MAGIC_uvar)) == NULL ||  magic->mg_private != MMAP_MAGIC_NUMBER)
		Perl_croak(aTHX_ "Could not %s: this variable is not memory mapped", funcname);
	return (struct mmap_info*) magic->mg_ptr;
}

#define YES &PL_sv_yes

MODULE = Sys::Mmap::Simple				PACKAGE = Sys::Mmap::Simple

PROTOTYPES: DISABLED

SV*
_mmap_impl(var, length, writable, fd, offset)
	SV* var = get_var(aTHX_ ST(0));
	size_t length;
	int writable;
	int fd;
	off_t offset;
	CODE:
		mmap_impl(aTHX_ var, length, writable, MAP_SHARED, fd, offset);
		ST(0) = &PL_sv_yes;

SV*
map_anonymous(var, length)
	SV* var = get_var(aTHX_ ST(0));
	size_t length;
	PROTOTYPE: \$@
	CODE:
		if (length == 0)
			Perl_croak(aTHX_ "Zero length specified for anonymous map");
		mmap_impl(aTHX_ var, length, TRUE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
		ST(0) = &PL_sv_yes;

SV*
sync(var, sync = YES)
	SV* var = get_var(aTHX_ ST(0));
	SV* sync;
	PROTOTYPE: \$@
	CODE:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "sync");
		if (msync(info->real_address, info->real_length, SvTRUE(sync) ? MS_SYNC : MS_ASYNC ) == -1)
			croak_sys(aTHX_ "Could not sync: %s");
		ST(0) = &PL_sv_yes;

#ifdef __linux__
SV*
remap(var, new_size)
	SV* var = get_var(aTHX_ ST(0));
	size_t new_size;
	PROTOTYPE: \$@
	CODE:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "remap");
		if (mremap(info->real_address, info->real_length, new_size + (info->real_length - info->fake_length), 0) == MAP_FAILED)
			croak_sys(aTHX_ "Could not remap: %s");
		ST(0) = &PL_sv_yes;

#endif /* __linux__ */

SV*
unmap(var)
	SV* var = get_var(aTHX_ ST(0));
	PROTOTYPE: \$
	CODE: 
		get_mmap_magic(aTHX_ var, "unmap");
		sv_unmagic(var, PERL_MAGIC_uvar);
		ST(0) = &PL_sv_yes;

SV*
pin(var)
	SV* var = get_var(aTHX_ ST(0));
	PROTOTYPE: \$
	CODE: 
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "pin");
		if (mlock(info->real_address, info->real_length) == -1)
			croak_sys(aTHX_ "Could not mlock: %s");
		ST(0) = &PL_sv_yes;

SV*
unpin(var)
	SV* var = get_var(aTHX_ ST(0));
	PROTOTYPE: \$
	CODE:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "unpin");
		if (munlock(info->real_address, info->real_length) == -1)
			croak_sys(aTHX_ "Could not munlock: %s");
		ST(0) = &PL_sv_yes;

void
locked(block, var)
	SV* block;
	SV* var = get_var(aTHX_ ST(1));
	PROTOTYPE: &\$
	INIT:
		struct mmap_info* info = get_mmap_magic(aTHX_ var, "do locked");
	PPCODE:
		SAVESPTR(DEFSV);
		DEFSV = var;
		PUSHMARK(SP);
#ifdef USE_ITHREADS
		MUTEX_LOCK(&info->data_mutex);
		call_sv(block, GIMME_V | G_EVAL | G_NOARGS);
		MUTEX_UNLOCK(&info->data_mutex);
		if (SvTRUE(ERRSV))
			Perl_croak(aTHX_ NULL);
#else
		call_sv(block, GIMME_V | G_NOARGS);
#endif
		SPAGAIN;

#ifdef USE_ITHREADS
void
condition_wait(block)
	SV* block;
	PROTOTYPE: &
	PPCODE:
		struct mmap_info* info = get_mmap_magic(aTHX_ DEFSV, "condition_wait");
		while (1) {
			PUSHMARK(SP);
			call_sv(block, G_SCALAR | G_NOARGS);
			SPAGAIN;
			if (SvTRUE(TOPs))
				break;
			POPs;
			COND_WAIT(&info->cond, &info->data_mutex);
		}

void
condition_signal()
	PROTOTYPE:
	CODE:
		struct mmap_info* info = get_mmap_magic(aTHX_ DEFSV, "condition_signal");
		COND_SIGNAL(&info->cond);

void
condition_broadcast()
	PROTOTYPE:
	CODE:
		struct mmap_info* info = get_mmap_magic(aTHX_ DEFSV, "condition_broadcast");
		COND_BROADCAST(&info->cond);

#endif /* USE ITHREADS */
