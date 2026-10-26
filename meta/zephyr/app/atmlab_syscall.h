__syscall struct k_container *atmlab_accept(struct k_container *obj);
__syscall ssize_t atmlab_read(struct k_container *obj, void *buffer, size_t count);
__syscall ssize_t atmlab_write(struct k_container *obj, const void *buffer, size_t count);
__syscall int atmlab_close(struct k_container *obj);
__syscall int atmlab_user_data_claim(const char *key, size_t key_len, const void *handle);
__syscall int atmlab_user_data_handle(const char *key, size_t key_len, void *handle);
__syscall int atmlab_user_data_write(const char *key, size_t key_len, const void *data, size_t data_len);
__syscall int atmlab_user_data_read(const char *key, size_t key_len, void *buf, size_t buf_len);
#include <zephyr/syscalls/atmlab_syscall.h>
