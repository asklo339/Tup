#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* --- Begin Header Section --- */

/* Remap System V shared memory API names.  
   Use <sys/shm.h> if available; if not, supply minimal definitions. */
#if __has_include(<sys/shm.h>)
  #include <sys/shm.h>
#else
  #include <sys/types.h>
  #include <time.h>
  /* Minimal definitions for ipc_perm and shmid_ds */
  struct ipc_perm {
      key_t key;
      uid_t uid;
      gid_t gid;
      uid_t cuid;
      gid_t cgid;
      unsigned short mode;
      unsigned short seq;
      unsigned short __pad1;
      unsigned short __pad2;
      unsigned long unused1;
      unsigned long unused2;
  };
  struct shmid_ds {
      struct ipc_perm shm_perm;
      size_t shm_segsz;
      time_t shm_atime;
      time_t shm_dtime;
      time_t shm_ctime;
      unsigned long shm_cpid;
      unsigned long shm_lpid;
      unsigned short shm_nattch;
      unsigned short unused_shm;  // renamed from __unused
      unsigned long __unused2;
  };
#endif

/* Ensure required IPC macros are defined */
#ifndef IPC_PRIVATE
# define IPC_PRIVATE ((key_t)0)
#endif
#ifndef IPC_RMID
# define IPC_RMID 0
#endif
#ifndef IPC_STAT
# define IPC_STAT 2
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Remap the System V functions to our libandroid_ implementations */
#undef shmctl
#define shmctl libandroid_shmctl
extern int libandroid_shmctl(int shmid, int cmd, struct shmid_ds *buf);

#undef shmget
#define shmget libandroid_shmget
extern int libandroid_shmget(key_t key, size_t size, int shmflg);

#undef shmat
#define shmat libandroid_shmat
extern void *libandroid_shmat(int shmid, const void *shmaddr, int shmflg);

#undef shmdt
#define shmdt libandroid_shmdt
extern int libandroid_shmdt(const void *shmaddr);

#ifdef __cplusplus
}
#endif

/* POSIX shared memory API declarations */
#ifndef POSIX_SHM_H
#define POSIX_SHM_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int shm_open(const char *name, int oflag, mode_t mode);
extern int shm_unlink(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* POSIX_SHM_H */

/* --- End Header Section --- */


/* --- Begin Implementation of System V Shared Memory Functions --- */

#ifdef ANDROID
#include <android/log.h>
#endif

#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>
#include <paths.h>
#include <ctype.h>
#include <libgen.h>

#define __u32 uint32_t

#ifdef ANDROID
#include <linux/ashmem.h>
#include <libgen.h>
#endif

/* DBG is defined empty */
#define DBG(...)  /* no debug output */

/* Used for naming the Unix socket for remote sharing */
#define ANDROID_SHMEM_SOCKNAME "/dev/shm/%08x"

/* Rounds up N to the nearest multiple of S */
#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
	/* The shmid (shared memory id) contains the socket address (16 bits)
	   and a local id (15 bits). */
	int id;
	void *addr;
	int descriptor;
	size_t size;
	bool markedForDeletion;
	key_t key;
} shmem_t;

static shmem_t* shmem = NULL;
static size_t shmem_amount = 0;
static uint8_t syscall_supported = 0;

#ifndef __LIBC_HIDDEN__
#define __LIBC_HIDDEN__
#endif

__LIBC_HIDDEN__ void android_shmem_sysv_shm_force(uint8_t enable) {
	syscall_supported = enable;
}

#define ANDROID_LINUX_SHM
#undef SYS_ipc

static bool isProot(void) {
	char buf[4096];
	char path[256];
	char exe_path[256];
	int tpid;
	int status_fd = open("/proc/self/status", O_RDONLY);
	if (status_fd == -1)
		return false;
	read(status_fd, buf, sizeof(buf) - 1);
	close(status_fd);
	const char *tracer_str = strstr(buf, "TracerPid:");
	if (tracer_str == NULL || sscanf(tracer_str, "TracerPid:   %d", &tpid) != 1 || !tpid)
		return false;
	snprintf(path, sizeof(path), "/proc/%d/exe", tpid);
	ssize_t len = readlink(path, exe_path, sizeof(exe_path) - 1);
	if (len == -1)
		return false;
	exe_path[len] = '\0';
	return (!strcmp(basename(exe_path), "proot"));
}

__attribute__((unused, constructor))
static void check_syscall_support(void) {
	if (!isProot())
		return;
	errno = 0;
#ifdef ANDROID_LINUX_SHM
#ifdef SYS_ipc
	syscall(SYS_ipc);
#else
	syscall(SYS_shmat);
#endif
#endif
	if (errno != ENOSYS)
		syscall_supported = 1;
}

/* Global state for socket-based sharing */
static int ashv_local_socket_id = 0;
static int ashv_pid_setup = 0;
static pthread_t ashv_listening_thread_id = 0;

static int ancil_send_fd(int sock, int fd)
{
    char nothing = '!';
    struct iovec nothing_ptr = { &nothing, 1 };

    struct {
        struct cmsghdr align;
        int fd[1];
    } ancillary_data_buffer;

    struct msghdr message_header = { 
        /* msg_name */      NULL,
        /* msg_namelen */   0,
        /* msg_iov */       &nothing_ptr,
        /* msg_iovlen */    1,
        /* msg_control */   &ancillary_data_buffer,
        /* msg_controllen */ sizeof(struct cmsghdr) + sizeof(int),
        /* msg_flags */     0
    };

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&message_header);
    cmsg->cmsg_len = message_header.msg_controllen;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    ((int*) CMSG_DATA(cmsg))[0] = fd;

    return sendmsg(sock, &message_header, 0) >= 0 ? 0 : -1;
}

static int ancil_recv_fd(int sock)
{
    char nothing = '!';
    struct iovec nothing_ptr = { &nothing, 1 };

    struct {
        struct cmsghdr align;
        int fd[1];
    } ancillary_data_buffer;

    struct msghdr message_header = {
        /* msg_name */      NULL,
        /* msg_namelen */   0,
        /* msg_iov */       &nothing_ptr,
        /* msg_iovlen */    1,
        /* msg_control */   &ancillary_data_buffer,
        /* msg_controllen */ sizeof(struct cmsghdr) + sizeof(int),
        /* msg_flags */     0
    };

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&message_header);
    cmsg->cmsg_len = message_header.msg_controllen;
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    ((int*) CMSG_DATA(cmsg))[0] = -1;

    if (recvmsg(sock, &message_header, 0) < 0)
        return -1;

    return ((int*) CMSG_DATA(cmsg))[0];
}

static int ashmem_get_size_region(int fd)
{
#ifdef ANDROID
	return TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_GET_SIZE, NULL));
#else
	return -1;
#endif
}

/*
 * Creates a new named ashmem region.
 */
static int ashmem_create_region(const char *name, size_t size)
{
#ifdef ANDROID
	int fd = open("/dev/ashmem", O_RDWR);
	if (fd < 0)
		return fd;
	char name_buffer[ASHMEM_NAME_LEN] = {0};
	strncpy(name_buffer, name, sizeof(name_buffer));
	name_buffer[sizeof(name_buffer)-1] = 0;
	int ret = ioctl(fd, ASHMEM_SET_NAME, name_buffer);
	if (ret < 0)
		goto error;
	ret = ioctl(fd, ASHMEM_SET_SIZE, size);
	if (ret < 0)
		goto error;
	return fd;
error:
	close(fd);
	return ret;
#else
	return -1;
#endif
}

static void ashv_check_pid(void)
{
	pid_t mypid = getpid();
	if (ashv_pid_setup == 0) {
		ashv_pid_setup = mypid;
	} else if (ashv_pid_setup != mypid) {
		DBG("%s: Cleaning to new pid=%d from oldpid=%d", __func__, mypid, ashv_pid_setup);
		ashv_pid_setup = mypid;
		ashv_local_socket_id = 0;
		ashv_listening_thread_id = 0;
		shmem_amount = 0;
		pthread_mutex_unlock(&mutex);
		if (shmem != NULL)
			free(shmem);
		shmem = NULL;
	}
}

static int ashv_shmid_from_counter(unsigned int counter)
{
	return ashv_local_socket_id * 0x10000 + counter;
}

static int ashv_socket_id_from_shmid(int shmid)
{
	return shmid / 0x10000;
}

static int ashv_find_local_index(int shmid)
{
	for (size_t i = 0; i < shmem_amount; i++)
		if (shmem[i].id == shmid)
			return (int)i;
	return -1;
}

static void* ashv_thread_function(void* arg)
{
	int sock = *(int*)arg;
	free(arg);
	struct sockaddr_un addr;
	socklen_t len = sizeof(addr);
	int sendsock;
	while ((sendsock = accept(sock, (struct sockaddr *)&addr, &len)) != -1) {
		int shmid;
		if (recv(sendsock, &shmid, sizeof(shmid), 0) != sizeof(shmid)) {
			DBG("%s: ERROR: recv() returned not %zu bytes", __func__, sizeof(shmid));
			close(sendsock);
			continue;
		}
		pthread_mutex_lock(&mutex);
		int idx = ashv_find_local_index(shmid);
		if (idx != -1) {
			if (write(sendsock, &shmem[idx].key, sizeof(key_t)) != sizeof(key_t)) {
				DBG("%s: ERROR: write failed: %s", __func__, strerror(errno));
			}
			if (ancil_send_fd(sendsock, shmem[idx].descriptor) != 0) {
				DBG("%s: ERROR: ancil_send_fd() failed: %s", __func__, strerror(errno));
			}
		} else {
			DBG("%s: ERROR: cannot find shmid 0x%x", __func__, shmid);
		}
		pthread_mutex_unlock(&mutex);
		close(sendsock);
		len = sizeof(addr);
	}
	DBG("%s: ERROR: listen() failed, thread stopped", __func__);
	return NULL;
}

static void android_shmem_delete(int idx)
{
	if (shmem[idx].descriptor)
		close(shmem[idx].descriptor);
	shmem_amount--;
	memmove(&shmem[idx], &shmem[idx+1], (shmem_amount - idx) * sizeof(shmem_t));
}

static int ashv_read_remote_segment(int shmid)
{
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	sprintf(&addr.sun_path[1], ANDROID_SHMEM_SOCKNAME, ashv_socket_id_from_shmid(shmid));
	int addrlen = sizeof(addr.sun_family) + strlen(&addr.sun_path[1]) + 1;
	int recvsock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (recvsock == -1) {
		DBG("%s: cannot create UNIX socket: %s", __func__, strerror(errno));
		return -1;
	}
	if (connect(recvsock, (struct sockaddr*) &addr, addrlen) != 0) {
		DBG("%s: Cannot connect to UNIX socket %s: %s, len %d", __func__, addr.sun_path + 1, strerror(errno), addrlen);
		close(recvsock);
		return -1;
	}
	if (send(recvsock, &shmid, sizeof(shmid), 0) != sizeof(shmid)) {
		DBG("%s: send() failed on socket %s: %s", __func__, addr.sun_path + 1, strerror(errno));
		close(recvsock);
		return -1;
	}
	key_t key;
	if (read(recvsock, &key, sizeof(key_t)) != sizeof(key_t)) {
		DBG("%s: ERROR: failed read", __func__);
		close(recvsock);
		return -1;
	}
	int descriptor = ancil_recv_fd(recvsock);
	if (descriptor < 0) {
		DBG("%s: ERROR: ancil_recv_fd() failed on socket %s: %s", __func__, addr.sun_path + 1, strerror(errno));
		close(recvsock);
		return -1;
	}
	close(recvsock);
	int size = ashmem_get_size_region(descriptor);
	if (size == 0 || size == -1) {
		DBG("%s: ERROR: ashmem_get_size_region() returned %d on socket %s: %s", __func__, size, addr.sun_path + 1, strerror(errno));
		return -1;
	}
	int idx = (int)shmem_amount;
	shmem_amount++;
	shmem = (shmem_t *)realloc(shmem, shmem_amount * sizeof(shmem_t));
	shmem[idx].id = shmid;
	shmem[idx].descriptor = descriptor;
	shmem[idx].size = size;
	shmem[idx].addr = NULL;
	shmem[idx].markedForDeletion = false;
	shmem[idx].key = key;
	return idx;
}

/* The following System V functions are remapped to our libandroid_ implementations */

int libandroid_shmget(key_t key, size_t size, int flags)
{
	(void) flags;
#ifdef ANDROID_LINUX_SHM
	if (syscall_supported) {
		if (size > PTRDIFF_MAX)
			size = SIZE_MAX;
#ifndef SYS_ipc
		return syscall(SYS_shmget, key, size, flags);
#else
		return syscall(SYS_ipc, IPCOP_shmget, key, size, flags);
#endif
	}
#endif

	ashv_check_pid();
	static size_t shmem_counter = 0;
	if (!ashv_listening_thread_id) {
		int sock = socket(AF_UNIX, SOCK_STREAM, 0);
		if (!sock) {
			DBG("%s: cannot create UNIX socket: %s", __func__, strerror(errno));
			errno = EINVAL;
			return -1;
		}
		int i;
		for (i = 0; i < 4096; i++) {
			struct sockaddr_un addr;
			int len;
			memset(&addr, 0, sizeof(addr));
			addr.sun_family = AF_UNIX;
			ashv_local_socket_id = (getpid() + i) & 0xffff;
			sprintf(&addr.sun_path[1], ANDROID_SHMEM_SOCKNAME, ashv_local_socket_id);
			len = sizeof(addr.sun_family) + strlen(&addr.sun_path[1]) + 1;
			if (bind(sock, (struct sockaddr *)&addr, len) != 0)
				continue;
			DBG("%s: bound UNIX socket %s in pid=%d", __func__, addr.sun_path + 1, getpid());
			break;
		}
		if (i == 4096) {
			DBG("%s: cannot bind UNIX socket, bailing out", __func__);
			ashv_local_socket_id = 0;
			errno = ENOMEM;
			return -1;
		}
		if (listen(sock, 4) != 0) {
			DBG("%s: listen failed", __func__);
			errno = ENOMEM;
			return -1;
		}
		int* socket_arg = (int *)malloc(sizeof(int));
		*socket_arg = sock;
		pthread_create(&ashv_listening_thread_id, NULL, &ashv_thread_function, socket_arg);
	}
	int shmid = -1;
	pthread_mutex_lock(&mutex);
	char symlink_path[256];
	/* If key is not IPC_PRIVATE, try to find an existing segment */
	if (key != IPC_PRIVATE) {
		sprintf(symlink_path, "%s/ashv_key_%d", _PATH_TMP, key);
		char path_buffer[256];
		char num_buffer[64];
		while (true) {
			int path_length = readlink(symlink_path, path_buffer, sizeof(path_buffer) - 1);
			if (path_length != -1) {
				path_buffer[path_length] = '\0';
				int shmid_temp = atoi(path_buffer);
				if (shmid_temp != 0) {
					int idx = ashv_find_local_index(shmid_temp);
					if (idx == -1) {
						idx = ashv_read_remote_segment(shmid_temp);
					}
					if (idx != -1) {
						pthread_mutex_unlock(&mutex);
						return shmem[idx].id;
					}
				}
				unlink(symlink_path);
			}
			if (shmid == -1) {
				shmem_counter = (shmem_counter + 1) & 0x7fff;
				shmid = ashv_shmid_from_counter(shmem_counter);
				sprintf(num_buffer, "%d", shmid);
			}
			if (symlink(num_buffer, symlink_path) == 0)
				break;
		}
	}
	int idx = (int)shmem_amount;
	char buf[256];
	sprintf(buf, ANDROID_SHMEM_SOCKNAME "-%d", ashv_local_socket_id, idx);
	shmem_amount++;
	if (shmid == -1) {
		shmem_counter = (shmem_counter + 1) & 0x7fff;
		shmid = ashv_shmid_from_counter(shmem_counter);
	}
	shmem = (shmem_t *)realloc(shmem, shmem_amount * sizeof(shmem_t));
	size = ROUND_UP(size, getpagesize());
	shmem[idx].size = size;
	shmem[idx].descriptor = ashmem_create_region(buf, size);
	shmem[idx].addr = NULL;
	shmem[idx].id = shmid;
	shmem[idx].markedForDeletion = false;
	shmem[idx].key = key;
	if (shmem[idx].descriptor < 0) {
		DBG("%s: ashmem_create_region() failed for size %zu: %s", __func__, size, strerror(errno));
		shmem_amount--;
		shmem = (shmem_t *)realloc(shmem, shmem_amount * sizeof(shmem_t));
		pthread_mutex_unlock(&mutex);
		return -1;
	}
	pthread_mutex_unlock(&mutex);
	return shmid;
}

void* libandroid_shmat(int shmid, const void *shmaddr, int shmflg)
{
#ifdef ANDROID_LINUX_SHM
	if (syscall_supported) {
#ifndef SYS_ipc
		return (void *)syscall(SYS_shmat, shmid, shmaddr, shmflg);
#else
		unsigned long ret;
		ret = syscall(SYS_ipc, IPCOP_shmat, shmid, shmflg, &shmaddr, shmaddr);
		return (ret > -(unsigned long)SHMLBA) ? (void *)ret : (void *)shmaddr;
#endif
	}
#endif
	ashv_check_pid();
	int socket_id = ashv_socket_id_from_shmid(shmid);
	void *addr;
	pthread_mutex_lock(&mutex);
	int idx = ashv_find_local_index(shmid);
	if (idx == -1 && socket_id != ashv_local_socket_id) {
		idx = ashv_read_remote_segment(shmid);
	}
	if (idx == -1) {
		DBG("%s: shmid %x does not exist", __func__, shmid);
		pthread_mutex_unlock(&mutex);
		errno = EINVAL;
		return (void*) -1;
	}
	if (shmem[idx].addr == NULL) {
		shmem[idx].addr = mmap((void*) shmaddr, shmem[idx].size,
							   PROT_READ | (shmflg == 0 ? PROT_WRITE : 0),
							   MAP_SHARED, shmem[idx].descriptor, 0);
		if (shmem[idx].addr == MAP_FAILED) {
			DBG("%s: mmap() failed for ID %x FD %d: %s", __func__, idx, shmem[idx].descriptor, strerror(errno));
			shmem[idx].addr = NULL;
		}
	}
	addr = shmem[idx].addr;
	DBG("%s: mapped addr %p for FD %d ID %d", __func__, addr, shmem[idx].descriptor, idx);
	pthread_mutex_unlock(&mutex);
	return addr ? addr : (void *)-1;
}

int libandroid_shmdt(const void *shmaddr)
{
#ifdef ANDROID_LINUX_SHM
	if (syscall_supported) {
#ifndef SYS_ipc
		return syscall(SYS_shmdt, shmaddr);
#else
		return syscall(SYS_ipc, IPCOP_shmdt, 0, 0, 0, shmaddr);
#endif
	}
#endif
	ashv_check_pid();
	pthread_mutex_lock(&mutex);
	for (size_t i = 0; i < shmem_amount; i++) {
		if (shmem[i].addr == shmaddr) {
			if (munmap(shmem[i].addr, shmem[i].size) != 0) {
				DBG("%s: munmap %p failed", __func__, shmaddr);
			}
			shmem[i].addr = NULL;
			DBG("%s: unmapped addr %p for FD %d ID %zu shmid %x", __func__, shmaddr, shmem[i].descriptor, i, shmem[i].id);
			if (shmem[i].markedForDeletion ||
				ashv_socket_id_from_shmid(shmem[i].id) != ashv_local_socket_id) {
				DBG("%s: deleting shmid %x", __func__, shmem[i].id);
				android_shmem_delete(i);
			}
			pthread_mutex_unlock(&mutex);
			return 0;
		}
	}
	pthread_mutex_unlock(&mutex);
	DBG("%s: invalid address %p", __func__, shmaddr);
	return 0;
}

int libandroid_shmctl(int shmid, int cmd, struct shmid_ds *buf)
{
#ifdef ANDROID_LINUX_SHM
	if (syscall_supported) {
#ifndef SYS_ipc
		return syscall(SYS_shmctl, shmid, cmd, buf);
#else
		return syscall(SYS_ipc, IPCOP_shmctl, shmid, cmd, 0, buf, 0);
#endif
	}
#endif
	ashv_check_pid();
	if (cmd == IPC_RMID) {
		DBG("%s: IPC_RMID for shmid=%x", __func__, shmid);
		pthread_mutex_lock(&mutex);
		int idx = ashv_find_local_index(shmid);
		if (idx == -1) {
			DBG("%s: shmid=%x does not exist locally", __func__, shmid);
			pthread_mutex_unlock(&mutex);
			return 0;
		}
		if (shmem[idx].addr) {
			shmem[idx].markedForDeletion = true;
		} else {
			android_shmem_delete(idx);
		}
		pthread_mutex_unlock(&mutex);
		return 0;
	} else if (cmd == IPC_STAT) {
		if (!buf) {
			DBG("%s: ERROR: buf == NULL for shmid %x", __func__, shmid);
			errno = EINVAL;
			return -1;
		}
		pthread_mutex_lock(&mutex);
		int idx = ashv_find_local_index(shmid);
		if (idx == -1) {
			DBG("%s: ERROR: shmid %x does not exist", __func__, shmid);
			pthread_mutex_unlock(&mutex);
			errno = EINVAL;
			return -1;
		}
		memset(buf, 0, sizeof(struct shmid_ds));
		buf->shm_segsz = shmem[idx].size;
		buf->shm_nattch = 1;
		buf->shm_perm.key = shmem[idx].key;
		buf->shm_perm.uid = geteuid();
		buf->shm_perm.gid = getegid();
		buf->shm_perm.cuid = geteuid();
		buf->shm_perm.cgid = getegid();
		buf->shm_perm.mode = 0666;
		buf->shm_perm.seq = 1;
		pthread_mutex_unlock(&mutex);
		return 0;
	}
	DBG("%s: cmd %d not implemented yet!", __func__, cmd);
	errno = EINVAL;
	return -1;
}

/* --- End System V Shared Memory Functions --- */


/* --- Begin Custom shm_open() and shm_unlink() Implementations --- */

#include <alloca.h>

#ifdef __ANDROID__
#define SHMDIR "/data/data/com.termux/files/usr/tmp/"
#else
#define SHMDIR "/dev/shm/"
#endif

/* Our custom implementations are provided with external linkage */
int shm_open(const char *name, int oflag, mode_t mode) {
	size_t namelen;
	char *fname;
	/* Skip leading '/' characters */
	while (name[0] == '/') ++name;
	if (name[0] == '\0') {
		errno = EINVAL;
		return -1;
	}
	namelen = strlen(name);
	fname = (char *) alloca(sizeof(SHMDIR) - 1 + namelen + 1);
	memcpy(fname, SHMDIR, sizeof(SHMDIR) - 1);
	memcpy(fname + sizeof(SHMDIR) - 1, name, namelen + 1);
	int fd = open(fname, oflag, mode);
	if (fd != -1) {
		int flags = fcntl(fd, F_GETFD, 0);
		flags |= FD_CLOEXEC;
		flags = fcntl(fd, F_SETFD, flags);
		if (flags == -1) {
			int save_errno = errno;
			close(fd);
			fd = -1;
			errno = save_errno;
		}
	}
	return fd;
}

int shm_unlink(const char *name) {
	size_t namelen;
	char *fname;
	while (name[0] == '/') ++name;
	if (name[0] == '\0') {
		errno = EINVAL;
		return -1;
	}
	namelen = strlen(name);
	fname = (char *) alloca(sizeof(SHMDIR) - 1 + namelen + 1);
	memcpy(fname, SHMDIR, sizeof(SHMDIR) - 1);
	memcpy(fname + sizeof(SHMDIR) - 1, name, namelen + 1);
	return unlink(fname);
}

/* --- End Custom shm_open/shm_unlink Implementations --- */
