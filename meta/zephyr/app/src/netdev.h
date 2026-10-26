#ifndef ATM_NETDEV_H_
#define ATM_NETDEV_H_

#include <zephyr/sys/clock.h>

#include "atm.h"

/*
 * Recieves a cell from the network.
 * If an ATM network device does not exist, this returns -ENODEV.
 * If the device is not ready yet, this returns -ENXIO.
 * If the timeout expires first, the buffer is set to NULL and the function returns -EAGAIN.
 */
int atm_netdev_rx(struct atm_cell_buffer **buffer, k_timeout_t timeout);

/*
 * Transmits a cell to the network.
 * If an ATM network device does not exist, this returns -ENODEV.
 * If the device is not ready yet, this returns -ENXIO.
 * If the transmit backlog is full, this returns -ENOBUFS and the caller keeps
 * ownership of the buffer.
 */
int atm_netdev_tx(struct atm_cell_buffer *buffer);

/*
 * Configures loopback mode on the device.
 * This is mostly useful for testing.
 * If an ATM network device does not exist, this returns -ENODEV.
 * If the device is not ready yet, this returns -ENXIO.
 */
int atm_netdev_set_loopback(bool enabled);

#endif /* ATM_NETDEV_H_ */
