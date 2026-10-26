#define DT_DRV_COMPAT atmlab_netdev

#include <zephyr/device.h>
#include <zephyr/drivers/pcie/pcie.h>
#include <zephyr/init.h>
#include <zephyr/irq.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/sys_io.h>

#include "atm.h"
#include "netdev.h"

LOG_MODULE_REGISTER(atm_netdev, CONFIG_ATM_LOG_LEVEL);

/* Queues and signaling semaphore */
K_FIFO_DEFINE(atm_netdev_rx_queue);
K_FIFO_DEFINE(atm_netdev_tx_queue);
K_SEM_DEFINE(atm_netdev_sem, 0, 1);

/* Heap for ATM cells */
K_HEAP_DEFINE(atm_netdev_heap, CONFIG_ATM_NETDEV_MSG_HEAP_SIZE);

void atm_cell_buffer_free(struct atm_cell_buffer *buffer)
{
    k_heap_free(&atm_netdev_heap, buffer);
}

struct atm_cell_buffer *atm_cell_buffer_alloc(void)
{
    return k_heap_alloc(&atm_netdev_heap, sizeof(struct atm_cell_buffer), K_NO_WAIT);
}

/* Receive and transmit threads */
struct k_thread atm_netdev_rx_thread;
K_KERNEL_STACK_DEFINE(atm_netdev_rx_stack, 2048);
struct k_thread atm_netdev_tx_thread;
K_KERNEL_STACK_DEFINE(atm_netdev_tx_stack, 2048);

/* MMIO registers */
#define MMIO_CONTROL 0
#define MMIO_STATUS 4
#define MMIO_RX_BUFFER 8
#define MMIO_TX_BUFFER 12
#define MMIO_IRQ_RESET_OFFSET 16 /* This just needs to do nothing */

/* Flag bits */
#define MMIO_CONTROL_RX_ENABLE (1 << 0)
#define MMIO_CONTROL_TX_TRIGGER (1 << 1)
#define MMIO_CONTROL_LOOPBACK (1 << 2)

#define MMIO_STATUS_RX_LOSS (1 << 0)
#define MMIO_STATUS_TX_LOSS (1 << 1)
#define MMIO_STATUS_LOWER_UP (1 << 2)

#define DMA_OWNER_SOFTWARE 0
#define DMA_OWNER_HARDWARE 1

#define DMA_NUM_DESCRIPTORS 64
#define NETDEV_TX_POLL_MS 10

/* Backlog limits for the two cell FIFOs, well above the 64-descriptor rings */
#define ATM_NETDEV_MAX_RX_CELLS 256
#define ATM_NETDEV_MAX_TX_CELLS 256

#if DT_HAS_COMPAT_STATUS_OKAY(DT_DRV_COMPAT)

/* Number of cells currently sitting in the queues above */
static atomic_t atm_netdev_rx_queued;
static atomic_t atm_netdev_tx_queued;

struct atm_netdev_config {
    struct pcie_dev *pcie;
    void (*irq_config_func)(const struct device *dev);
};

struct atm_netdev_data {
    DEVICE_MMIO_RAM;
    struct atm_netdev_dma_descriptor *rx_head;
    struct atm_netdev_dma_descriptor *tx_head;
};

struct atm_netdev_dma_descriptor {
    struct atm_netdev_dma_descriptor* next;
    uint32_t owner : 1;
    uint32_t _unused : 31;
    uint8_t *buffer;
};

static void atm_netdev_rx_process(struct atm_netdev_data *data)
{
    while (data->rx_head->owner == DMA_OWNER_SOFTWARE) {
        /* Allocate a replacement buffer so the DMA chain always stays filled */
        struct atm_cell_buffer *replacement_buffer = NULL;
        if (atomic_get(&atm_netdev_rx_queued) < ATM_NETDEV_MAX_RX_CELLS)
            replacement_buffer = atm_cell_buffer_alloc();

        if (replacement_buffer == NULL) {
            /* Drop the cell: hand the descriptor back with its existing buffer */
            LOG_WRN_RATELIMIT("receive backlog full, dropping cell");
        } else {
            /* Extract the current buffer from the DMA descriptor, and replace it with the new one */
            struct atm_cell_buffer *buffer = ATM_CELL_TO_CELL_BUFFER(data->rx_head->buffer);
            data->rx_head->buffer = replacement_buffer->buffer;

            /* Put the cell into the receive queue */
            atomic_inc(&atm_netdev_rx_queued);
            k_fifo_put(&atm_netdev_rx_queue, buffer);
        }

        /* Now, the data->rx_headriptor is hardware-owned again. But the device has moved on. */
        data->rx_head->owner = DMA_OWNER_HARDWARE;
        data->rx_head = data->rx_head->next;
    }
}

static void atm_netdev_rx_task(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1);
    ARG_UNUSED(p2);
    ARG_UNUSED(p3);

    const struct device *dev = DEVICE_DT_GET(DT_INST(0, DT_DRV_COMPAT));
    struct atm_netdev_data *data = (struct atm_netdev_data *) dev->data;

    while (true) {
        k_sem_take(&atm_netdev_sem, K_FOREVER);
        atm_netdev_rx_process(data);
        /* TODO: Unmask the interrupt, then call atm_netdev_rx_process again to clean up any stragglers where we ate the interrupt. */
    }
}

static void atm_netdev_tx_trigger(const struct device *dev)
{
    mm_reg_t mmio = DEVICE_MMIO_GET(dev);
    uint32_t control = sys_read32(mmio + MMIO_CONTROL);
    sys_write32(control | MMIO_CONTROL_TX_TRIGGER, mmio + MMIO_CONTROL);
}

static void atm_netdev_tx_task(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1);
    ARG_UNUSED(p2);
    ARG_UNUSED(p3);

    const struct device *dev = DEVICE_DT_GET(DT_INST(0, DT_DRV_COMPAT));
    struct atm_netdev_data *data = (struct atm_netdev_data *) dev->data;

    while (true) {
        struct atm_cell_buffer *buffer = k_fifo_get(&atm_netdev_tx_queue, K_FOREVER);
        atomic_dec(&atm_netdev_tx_queued);

        do {
            while (data->tx_head->owner == DMA_OWNER_HARDWARE) {
                /* Dear device, please hurry. */
                atm_netdev_tx_trigger(dev);
                k_sleep(K_MSEC(NETDEV_TX_POLL_MS));
            }

            if (data->tx_head->buffer != NULL) {
                struct atm_cell_buffer *old_buffer = ATM_CELL_TO_CELL_BUFFER(data->tx_head->buffer);
                atm_cell_buffer_free(old_buffer);
            }

            LOG_DBG("Submitting cell at %p", buffer->buffer);
            data->tx_head->buffer = buffer->buffer;
            data->tx_head->owner = DMA_OWNER_HARDWARE;
            data->tx_head = data->tx_head->next;
            buffer = k_fifo_get(&atm_netdev_tx_queue, K_NO_WAIT);
            if (buffer)
                atomic_dec(&atm_netdev_tx_queued);
        } while (buffer);

        atm_netdev_tx_trigger(dev);
    }
}

static void atm_netdev_rx_isr(const void *arg)
{
    const struct device *dev = arg;

    /* TODO: Mask the interrupt */

    /* Signal to the receive thread */
    k_sem_give(&atm_netdev_sem);

    /*
     * I hate my life: we need to read from a BAR to signal INTx EOI.
     * Otherwise we're stuck with a signaled INTx forever.
     * See the comments in QEMU's hw/vfio/region.c for that particular insight.
     */
    sys_read8(DEVICE_MMIO_GET(dev) + MMIO_IRQ_RESET_OFFSET);
}

#define ATM_NETDEV_IRQ_CONFIG(n)                                         \
    static void atm_netdev_irq_config_func_##n(const struct device *dev) \
    {                                                                    \
        const struct atm_netdev_config *cfg = dev->config;               \
        unsigned int irq;                                                \
        if (DT_INST_IRQN(n) == PCIE_IRQ_DETECT) {                        \
            irq = pcie_get_irq(cfg->pcie->bdf);                          \
            if (irq == PCIE_CONF_INTR_IRQ_NONE) {                        \
                return;                                                  \
            }                                                            \
            if (!pcie_connect_dynamic_irq(cfg->pcie->bdf, irq,           \
                                          DT_INST_IRQ(n, priority),      \
                                          atm_netdev_rx_isr, dev, 0)) {  \
                return;                                                  \
            }                                                            \
            pcie_irq_enable(cfg->pcie->bdf, irq);                        \
            return;                                                      \
        }                                                                \
        IRQ_CONNECT(DT_INST_IRQN(n), DT_INST_IRQ(n, priority),           \
                    atm_netdev_rx_isr, DEVICE_DT_INST_GET(n), 0);        \
        irq_enable(DT_INST_IRQN(n));                                     \
        pcie_irq_enable(cfg->pcie->bdf, DT_INST_IRQN(n));                \
    }

#define ATM_NETDEV_IRQ_FUNC_DECLARE(n) \
    static void atm_netdev_irq_config_func_##n(const struct device *dev);

#define ATM_NETDEV_IRQ_FUNC_DEFINE(n) ATM_NETDEV_IRQ_CONFIG(n)

#define DEV_CONFIG_PCIE_IRQ_FUNC_INIT(n) \
    .irq_config_func = atm_netdev_irq_config_func_##n,

static int atm_netdev_init_descriptors(const struct device *dev)
{
    struct atm_netdev_data *data = (struct atm_netdev_data *) dev->data;

    /* Allocate descriptors */
    struct atm_netdev_dma_descriptor *rx_descriptors = k_calloc(DMA_NUM_DESCRIPTORS, sizeof(struct atm_netdev_dma_descriptor));
    struct atm_netdev_dma_descriptor *tx_descriptors = k_calloc(DMA_NUM_DESCRIPTORS, sizeof(struct atm_netdev_dma_descriptor));
    if (!rx_descriptors || !tx_descriptors) {
        LOG_ERR("Failed to allocate DMA descriptors");
        return -ENOMEM;
    }
    data->rx_head = rx_descriptors;
    data->tx_head = tx_descriptors;

    /* Set up the cyclic descriptor chain */
    for (int i = 0; i < DMA_NUM_DESCRIPTORS - 1; i++) {
        rx_descriptors[i].next = &rx_descriptors[i+1];
        tx_descriptors[i].next = &tx_descriptors[i+1];
    }
    rx_descriptors[DMA_NUM_DESCRIPTORS - 1].next = &rx_descriptors[0];
    tx_descriptors[DMA_NUM_DESCRIPTORS - 1].next = &tx_descriptors[0];

    /* Allocate receive buffers */
    for (int i = 0; i < DMA_NUM_DESCRIPTORS; i++) {
        struct atm_cell_buffer *buffer = k_heap_alloc(&atm_netdev_heap, sizeof(struct atm_cell_buffer), K_NO_WAIT);
        if (!buffer) {
            LOG_ERR("Failed to allocate receive buffer");
            return -ENOMEM;
        }
        rx_descriptors[i].buffer = buffer->buffer;
        rx_descriptors[i].owner = DMA_OWNER_HARDWARE;
    }
    return 0;
}

static int atm_netdev_init(const struct device *dev)
{
    const struct atm_netdev_config *cfg = dev->config;
    struct atm_netdev_data *data = (struct atm_netdev_data *) dev->data;
    struct pcie_bar mbar;
    int result;
    mm_reg_t mmio;

    /* Set up and map the PCI device */
    if (!cfg->pcie || cfg->pcie->bdf == PCIE_BDF_NONE)
        return -EINVAL;

    if (!pcie_probe_mbar(cfg->pcie->bdf, 0, &mbar))
        return -EINVAL;

    pcie_set_cmd(cfg->pcie->bdf, PCIE_CONF_CMDSTAT_MEM, true);
    pcie_set_cmd(cfg->pcie->bdf, PCIE_CONF_CMDSTAT_MASTER, true);

    device_map(DEVICE_MMIO_RAM_PTR(dev), mbar.phys_addr, mbar.size, K_MEM_CACHE_NONE);
    LOG_DBG("Device is mapped at 0x%lx", DEVICE_MMIO_GET(dev));

    /* Configure IRQs */
    if (cfg->irq_config_func)
        cfg->irq_config_func(dev);

    /* Initialize DMA descriptors */
    if ((result = atm_netdev_init_descriptors(dev))) {
        LOG_ERR("Failed to initialize DMA (%d)", result);
        return result;
    }

    /*
     * Start the receive and transmit threads.
     * Priority -1 on the receive thread means it will not be prempted.
     */
    k_thread_create(&atm_netdev_rx_thread, atm_netdev_rx_stack,
            K_KERNEL_STACK_SIZEOF(atm_netdev_rx_stack),
            atm_netdev_rx_task, NULL, NULL, NULL, -1, 0, K_NO_WAIT);
    k_thread_create(&atm_netdev_tx_thread, atm_netdev_tx_stack,
            K_KERNEL_STACK_SIZEOF(atm_netdev_tx_stack),
            atm_netdev_tx_task, NULL, NULL, NULL, 0, 0, K_NO_WAIT);

    /* Configure the device for DMA */
    mmio = DEVICE_MMIO_GET(dev);
    sys_write32((uintptr_t) data->rx_head, mmio + MMIO_RX_BUFFER);
    sys_write32((uintptr_t) data->tx_head, mmio + MMIO_TX_BUFFER);

    /* Start receiving cells */
    uint32_t control = sys_read32(mmio + MMIO_CONTROL);
    sys_write32(control | MMIO_CONTROL_RX_ENABLE, mmio + MMIO_CONTROL);

    return 0;
}

#define ATM_NETDEV_INIT(n)                                          \
    ATM_NETDEV_IRQ_FUNC_DECLARE(n);                                 \
    DEVICE_PCIE_INST_DECLARE(n);                                    \
    static const struct atm_netdev_config atm_netdev_cfg_##n = {    \
        DEV_CONFIG_PCIE_IRQ_FUNC_INIT(n)                            \
        DEVICE_PCIE_INST_INIT(n, pcie)                              \
    };                                                              \
    static struct atm_netdev_data atm_netdev_data_##n = {           \
    };                                                              \
    DEVICE_DT_INST_DEFINE(n, atm_netdev_init, NULL,                 \
                  &atm_netdev_data_##n, &atm_netdev_cfg_##n,        \
                  POST_KERNEL, CONFIG_PCIE_INIT_PRIORITY,           \
                  NULL);                                            \
    ATM_NETDEV_IRQ_FUNC_DEFINE(n)

DT_INST_FOREACH_STATUS_OKAY(ATM_NETDEV_INIT);

int atm_netdev_rx(struct atm_cell_buffer **buffer, k_timeout_t timeout)
{

    if (buffer == NULL) {
        LOG_ERR("buffer is NULL");
        return -EINVAL;
    }

    const struct device *dev = DEVICE_DT_GET(DT_INST(0, DT_DRV_COMPAT));
    if (!device_is_ready(dev))
        return -ENXIO;

    struct atm_cell_buffer *cell = k_fifo_get(&atm_netdev_rx_queue, timeout);
    *buffer = cell;
    if (!cell)
        return -EAGAIN;

    atomic_dec(&atm_netdev_rx_queued);
    return 0;
}

int atm_netdev_tx(struct atm_cell_buffer *buffer)
{
    const struct device *dev = DEVICE_DT_GET(DT_INST(0, DT_DRV_COMPAT));
    if (!device_is_ready(dev))
        return -ENXIO;

    /* Several threads submit here, so claim the slot before checking it */
    if (atomic_inc(&atm_netdev_tx_queued) >= ATM_NETDEV_MAX_TX_CELLS) {
        atomic_dec(&atm_netdev_tx_queued);
        LOG_WRN_RATELIMIT("transmit backlog full, dropping cell");
        return -ENOBUFS;
    }

    k_fifo_put(&atm_netdev_tx_queue, buffer);
    return 0;
}

int atm_netdev_set_loopback(bool enabled)
{
    const struct device *dev = DEVICE_DT_GET(DT_INST(0, DT_DRV_COMPAT));
    if (!device_is_ready(dev))
        return -ENXIO;

    uint32_t flag = enabled ? MMIO_CONTROL_LOOPBACK : 0;

    mm_reg_t mmio = DEVICE_MMIO_GET(dev);
    uint32_t control = sys_read32(mmio + MMIO_CONTROL);
    if ((control & MMIO_CONTROL_LOOPBACK) != flag)
        sys_write32((control & ~MMIO_CONTROL_LOOPBACK) | flag, mmio + MMIO_CONTROL);
    return 0;
}

#else

int atm_netdev_rx(struct atm_cell_buffer **buffer, k_timeout_t timeout)
{
    return -ENODEV;
}

int atm_netdev_tx(struct atm_cell_buffer *buffer)
{
    return -ENODEV;
}

int atm_netdev_set_loopback(bool enabled)
{
    return -ENODEV;
}

#endif /* DT_HAS_COMPAT_STATUS_OKAY(DT_DRV_COMPAT) */
