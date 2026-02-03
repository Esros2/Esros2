#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <link.h>
#include <elf.h>

/* -------------------- CONFIG -------------------- */

#define FIXED_ADDR   ((void *)0x700000000000UL)
#define PAGE_SIZE    4096
#define MAX_THREADS  100

/* ---------------- Trusted libraries ---------------- */

static const char *trusted_libs[] = {
    "libwrapper.so",
    "librosidl_runtime_c.so",
    "librosidl_typesupport_cpp.so",
    "librosidl_typesupport_c.so",
    "librosidl_typesupport_fastrtps_cpp.so",
    "librosidl_typesupport_fastrtps_c.so",
    "librosidl_typesupport_introspection_cpp.so",
    "librosidl_typesupport_introspection_c.so",

    "librcutils.so",
    "librcpputils.so",
    "libstatistics_collector.so",

    "librcl.so",
    "librcl_action.so",
    "librcl_lifecycle.so",
    "librcl_yaml_param_parser.so",
    "librcl_logging_interface.so",
    "librcl_logging_spdlog.so",

    "librclcpp.so",
    "librclcpp_action.so",
    "librclcpp_lifecycle.so",

    "librmw.so",
    "librmw_implementation.so",
    "librmw_dds_common.so",
    "librmw_fastrtps_cpp.so",
    "librmw_fastrtps_shared_cpp.so",

    "libament_index_cpp.so",
    "libclass_loader.so",
    "libcomponent_manager.so",

    "libfastcdr.so",
    "libfastrtps.so",

    "librmw_cyclonedds_cpp.so",
    "librmw_connextdds.so",
    "librmw_gurumdds_cpp.so",
    "librosidl_runtime_cpp.so",
    "librosidl_typesupport_interface.so",
    "librcl_logging_noop.so",
    "librcl_components.so",
};

/* -------------------- TCB DATA -------------------- */

typedef struct {
    uint32_t thread_id;
    uint32_t counter;
} countTable;

_Static_assert(sizeof(countTable) == 8, "countTable must be 8 bytes");
_Static_assert(sizeof(countTable) * MAX_THREADS <= PAGE_SIZE,
               "TCB table must fit in one page");

/* -------------------- GLOBAL STATE -------------------- */

static int   pkey_tcb = -1;
static int   pkey_lib = -1;
static void *tcb_addr = NULL;

/* -------------------- HELPERS -------------------- */

static int is_trusted_library(const char *path)
{
    if (!path || path[0] == '\0')
        return 0;

    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;

    for (size_t i = 0;
         i < sizeof(trusted_libs) / sizeof(trusted_libs[0]);
         i++) {
        if (strcmp(base, trusted_libs[i]) == 0)
            return 1;
    }
    return 0;
}

/* -------------------- ELF CALLBACK -------------------- */
/* ONLY assigns pkey to writable data segments */

static int phdr_callback(struct dl_phdr_info *info,
                         size_t size,
                         void *data)
{
    
    if (!is_trusted_library(info->dlpi_name))
        return 0;
  // printf("%s\n",info->dlpi_name);

    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *phdr = &info->dlpi_phdr[i];

        if (phdr->p_type != PT_LOAD)
            continue;
        if (!(phdr->p_flags & PF_W))
            continue;   /* only writable data */

        uintptr_t start = info->dlpi_addr + phdr->p_vaddr;
        uintptr_t end   = start + phdr->p_memsz;

        long ps = sysconf(_SC_PAGESIZE);
        uintptr_t astart = start & ~(ps - 1);
        uintptr_t aend   = (end + ps - 1) & ~(ps - 1);

        if (pkey_mprotect((void *)astart,
                          aend - astart,
                          PROT_READ | PROT_WRITE,
                          pkey_lib) != 0) {
            perror("pkey_mprotect (lib)");
        }
    }
    return 0;
}


__attribute__((constructor))
static void init_tcb_region(void)
{
    // Map once
    void *addr = mmap(FIXED_ADDR,
                      PAGE_SIZE,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                      -1, 0);

    if (addr == MAP_FAILED) {
        perror("[mpk] mmap TCB");
        _exit(1);
    }

    // Initialize it
    countTable *table = (countTable *)addr;
    for (int i = 0; i < MAX_THREADS; i++) {
        table[i].thread_id = 0;
        table[i].counter   = 0;
    }

    // fprintf(stderr,
    //     "[mpk] TCB mapped RW early at %p\n",
    //     addr);

    // DO NOT assign pkeys yet — wrapper may need read/write!
}




/* -------------------- PUBLIC API -------------------- */
/* Call this ONCE, after main() starts */

void protect_trusted_libraries_with_pkey(void)
{
    //printf("[mpk] Initializing MPK protections...\n");

    if (pkey_tcb == -1 && pkey_lib == -1) {
        pkey_tcb = pkey_alloc(0, 0);
        pkey_lib = pkey_alloc(0, 0);

        if (pkey_tcb < 0 || pkey_lib < 0) {
            perror("pkey_alloc");
            _exit(1);
        }
    }

   if (pkey_mprotect((void *)FIXED_ADDR,
                  PAGE_SIZE,
                  PROT_READ | PROT_WRITE,
                  pkey_tcb) != 0) {
    perror("[mpk] pkey_mprotect TCB");
    _exit(1);
}

    // fprintf(stderr,
    //     "[mpk] TCB protected RO (pkey=%d)\n",
    //     pkey_tcb);

    // Assign RW permission to trusted libraries
        dl_iterate_phdr(phdr_callback, NULL);

    // fprintf(stderr,
    //     "[mpk] trusted libraries mapped RW (pkey=%d)\n",
    //     pkey_lib);
}
