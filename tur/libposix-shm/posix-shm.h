#ifndef _MY_SHM_H
#define _MY_SHM_H

#include <linux/shm.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* If shmid_ds is not defined, use shmid64_ds */
#ifndef shmid_ds
# define shmid_ds shmid64_ds
#endif

/* --- System V Shared Memory Functions --- */

/* Rename System V functions to libandroid_* versions.
   Applications using this header will call shmctl, shmget, shmat, and shmdt,
   which are redefined here to the corresponding libandroid_* implementations. */
#undef shmctl
#define shmctl libandroid_shmctl
extern int libandroid_shmctl(int shmid, int cmd, struct shmid_ds* buf);

#undef shmget
#define shmget libandroid_shmget
extern int libandroid_shmget(key_t key, size_t size, int shmflg);

#undef shmat
#define shmat libandroid_shmat
extern void* libandroid_shmat(int shmid, const void* shmaddr, int shmflg);

#undef shmdt
#define shmdt libandroid_shmdt
extern int libandroid_shmdt(const void* shmaddr);

/* --- POSIX Shared Memory Functions --- */

/* An implementation of shm_open() and shm_unlink() from the GNU C Library. */
int shm_open(const char *name, int oflag, mode_t mode);
int shm_unlink(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* _MY_SHM_H */
