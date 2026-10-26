#ifndef SOCKET_ATM_H_
#define SOCKET_ATM_H_

#include <sys/types.h>

/*
 * Create a socket for signaling that can still be used after the thread switches to usermode
 */
struct k_container *atm_create_signal_socket(uint32_t vpi, uint32_t vci);

#endif
