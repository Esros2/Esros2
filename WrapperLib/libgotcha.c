#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include <unistd.h>

#include <gotcha/gotcha.h>

#define MAX_BINDINGS 20000  

// ---------------- Allowlist ----------------
static const char *const kAllowLibs[] = {

    "irobot_node",
    "libstd_msgs__rosidl_typesupport_cpp.so",
    "libstatistics_msgs__rosidl_typesupport_cpp.so",
    "libtracetools.so",
    "libstdc++.so.6",
    "libgcc_s.so.1",
    "librcl_interfaces__rosidl_typesupport_cpp.so",
    "librosgraph_msgs__rosidl_typesupport_cpp.so",
    "libm.so.6",
    "librcl_interfaces__rosidl_typesupport_c.so",
    "librcl_interfaces__rosidl_generator_c.so",
    "libyaml.so",
    "libspdlog.so.1",
    "libbuiltin_interfaces__rosidl_generator_c.so",
    "libfmt.so.8",    

};





static const size_t kAllowLibsCount = sizeof(kAllowLibs) / sizeof(kAllowLibs[0]);

// ---------------- Helpers ----------------
static const char *basename_const(const char *path) {
    if (!path || !*path)
        return "";
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

// Cache the executable name (/proc/self/exe)
static const char *main_exe_basename(void) {
    static char resolved[256];
    static int inited = 0;
    if (!inited) {
        ssize_t n = readlink("/proc/self/exe", resolved, sizeof(resolved) - 1);
        resolved[(n > 0) ? n : 0] = '\0';
        inited = 1;
    }
    return basename_const(resolved);
}

// Exact match OR lib.so.N match
static int so_name_matches(const char *name, const char *pattern) {
    if (!name || !*name)
        name = main_exe_basename();

    if (!pattern)
        return 0;

    if (strcmp(name, pattern) == 0)
        return 1;

//    printf("Checking SONAME match: name='%s' pattern='%s'\n", name, pattern);
    size_t plen = strlen(pattern);
    if (plen >= 3 && strcmp(pattern + plen - 3, ".so") == 0) {
        if (strncmp(name, pattern, plen) == 0 && name[plen] == '.')
            return 1;
    }
    return 0;
}

static int is_allowed_soname(const char *base) {
    for (size_t i = 0; i < kAllowLibsCount; ++i) {
        if (so_name_matches(base, kAllowLibs[i]))
            return 1;
    }
    return 0;
}

// ---------------- GOTCHA Filter ----------------
static int my_gotcha_filter(struct link_map *map) {
    const char *path = (map && map->l_name) ? map->l_name : "";
    const char *base = basename_const(path);
    return is_allowed_soname(base) ? 1 : 0;
}

// ---------------- Dynamic Wrapping ----------------
static gotcha_binding_t bindings[MAX_BINDINGS];
static gotcha_wrappee_handle_t func_handles[MAX_BINDINGS];
static int binding_count = 0;

static void init_gotcha(void) {
    FILE *fp = fopen("~/libWrapper/PolicyFN.txt", "r");
    if (!fp) return;

    void *handle = dlopen("~/libWrapper/libwrapper.so", RTLD_NOW);
    if (!handle) {
        fclose(fp);
        return;
    }

        char func_name[256];
        while (fscanf(fp, "%255s", func_name) == 1 && binding_count < MAX_BINDINGS) {

            fflush(stdout);

            char wrapper_name[300];

             // C function
            snprintf(wrapper_name, sizeof(wrapper_name), "%s_wrapper", func_name);
        
            void *wrapper = dlsym(handle, wrapper_name);
            if (!wrapper) {
            //    printf(" [!] No wrapper found for %s\n", func_name);
                continue;
            }

            bindings[binding_count].name = strdup(func_name);
            bindings[binding_count].wrapper_pointer = wrapper;
            bindings[binding_count].function_handle = &func_handles[binding_count];

            gotcha_wrap(&bindings[binding_count], 1, "dynamic_wrap");

            binding_count++;
        }

    fclose(fp);
}


// ---------------- Constructor ----------------
__attribute__((constructor))
static void init_gotcha_wrapper(void) {
    gotcha_set_library_filter_func(&my_gotcha_filter);
    init_gotcha();
}

