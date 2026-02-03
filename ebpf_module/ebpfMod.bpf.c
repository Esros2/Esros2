#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>



pid_t target_pid = -1;


extern void bpf_sha256(struct file *, char *, unsigned long int) __ksym;


char _license[] SEC("license") = "GPL";

struct
{
	__u64 vm_start;
	__u64 vm_end;
} vm_ranges[1000];

typedef struct instz
{
	u8 libIndex;
	u8 pageNo;
} hash_key;

typedef struct insta
{
	char pageData[SHA256_BLOCK_SIZE];
	u64 size;
	char Zeros[32];

} page_wise_data;

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_LIB);
	__type(key, u64);
	__type(value, page_wise_data);
} libHash SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u64);
	__type(value, struct insta);
} bufff SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u64);
	__type(value, u64);
} mmap_flag SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_LIB);
	__type(key, u64);
	__type(value, u64);
} white_list_lib SEC(".maps");

struct c
{
	char lib[100];
	u8 index;
	bool ans;
};

struct white_list_ctx
{
	u64 libIndex;
	bool ans;
};

struct ctx
{
	char name[11];
	int flag;
};

typedef struct cd
{
	int zeros[32];
} Zeros;

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 210);
	__type(key, u64);
	__type(value, Zeros);
} ZerosAtLib SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, MAX_LIB);
} AlreadyComputedHash SEC(".maps");

typedef struct StringArgs
{
	u16 sys_id;
	u16 order;
	char val[100];
} StringArgsData;

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, StringArgsData);
	__type(value, u16);
	__uint(max_entries, 1000);
} StringArgMap SEC(".maps");



char file[100];

struct exec_params_t
{
    u64 __unused;
    u64 __unused2;

    char *file;
    char *argv;
    char *envp;
};


SEC("tp/syscalls/sys_enter_execve")
int wow(struct exec_params_t *params)
{
	 	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
			u32 pkru = task->thread.pkru;

	int ppid = task->pid;
	unsigned long r;

	if (target_pid == -1)
	{
		file[100];
		bpf_probe_read(file, sizeof(file), params->file);
		char *app = "./fib_single_process";
		bool flag = 0;
		for (int i = 0; i < 20; i++)
		{
			if (file[i] != app[i])
			{
				flag = 1;
				break;
			}
		}
		if (!flag)
		{
			target_pid = ppid;
            bpf_printk("We got ppiddd :: %d", ppid);
		
        }
    }
    return 0;
}


struct countTable {
    __u32 thread_id;
    __u32 counter;
};

#define FIXED_ADDR 0x700000000000ULL

SEC("tp_btf/sys_enter")
int main_entry_raw(struct bpf_raw_tracepoint_args *ctx)
{


	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	__u32 tid  = id & 0xffffffff;

	if (tgid != target_pid)
		return 0;


	__u32 cur_tid = bpf_get_current_pid_tgid() & 0xffffffff;
    struct countTable entry = {};
    const int MAX = 100;
    __u64 addr;
    /* bounded loop */
	bool flag = 0;
    #pragma clang loop unroll(full)
    for (int i = 0; i < MAX; i++) {
        addr = FIXED_ADDR + ((__u64)i * sizeof(struct countTable));
        if (bpf_probe_read_user(&entry, sizeof(entry), (void *)addr))
            continue;
		// bpf_printk("Reading slot %d: tid=%u counter=%u\n",
		// 		   i, entry.thread_id, entry.counter);
        if (entry.thread_id == tid) {
			flag = 1; 
            bpf_printk("slot=%d tid=%u counter=%u\n",
                       i, entry.thread_id, entry.counter);
        }
    }
	if(!flag){
		bpf_printk("No entry found for tid=%u, and system call is %u\n", tid,ctx->args[1]);
	}

    return 0;
}




char file[100];
static int callbackfun(struct bpf_map *map, long long unsigned int *key, libName *value, struct c *ctx)
{
	bool flag = 0;
	int i = 0;

	const char temp[100];
	bpf_probe_read(temp, sizeof(temp), value->name);
	int len = 0;

	while (i < 100)
	{
		if (bpf_strncmp(value->name + i, 1, "$") == 0)
			break;

		if (ctx->lib[i] != value->name[i])
		{
			return 0;
		}
		i++;
	}
	ctx->index = *key;
	return 0;
}


SEC("lsm/mmap_file")
int BPF_PROG(check_file_open, struct file *f, unsigned long reqprot, unsigned long prot, unsigned long flags, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	int ppid = task->pid;
	if (ppid != target_pid)
		return 0;
	if (f)
	{
		struct c ctx;
		ctx.index = MAX_LIB + 1;
		char *filename = f->f_path.dentry->d_name.name;
		char name[100];
		bpf_probe_read(name, sizeof(name), filename);
		bpf_probe_read_str((void *)ctx.lib, sizeof(ctx.lib), (const void *)filename);
		bpf_for_each_map_elem(&Mapping, callbackfun, &ctx, 0);
	
		u64 libIndexx = ctx.index;
		u64 *isAlreadyComputed = bpf_map_lookup_elem(&AlreadyComputedHash, &libIndexx);

		if (isAlreadyComputed)
			return 0;

		for (u64 i = 0; i < MAX_LIB; i++)
		{
			u64 key = i;
			u64 *val = bpf_map_lookup_elem(&white_list_lib, &key);
			if (val)
			{
				if (*val == ctx.index)
				{
					char digest[SHA256_BLOCK_SIZE + 1];
					u64 kk = ctx.index;
					page_wise_data *pg = bpf_map_lookup_elem(&libHash, &kk);
					if (pg)
					{
						unsigned long int size = pg->size;
							bpf_sha256(f, digest, size);
						for (int i = 0; i < SHA256_BLOCK_SIZE; i++)
						{
	//						bpf_printk("Digest : %x and pageData : %x and zeros %d,", digest[i], pg->pageData[i], pg->Zeros[i]);
							if (digest[i] != pg->pageData[i])
							{
								if (pg->Zeros[i] == 2 && digest[i] == 0 && pg->pageData[i] == 1)
									continue;

								bpf_send_signal(19);
								return 0;
							}
	
						}
					}
					u64 keyy = ctx.index;
					u64 valll = 1;
					bpf_map_update_elem(&AlreadyComputedHash, &keyy, &valll, 0);
					return 0;
				}
			}
		}
	}
	return 0;
}