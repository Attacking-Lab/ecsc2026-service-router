#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(test_atm_netdev, CONFIG_SELFTEST_LOG_LEVEL);

void test_atm_netdev(void)
{
    LOG_INF("Beginning selftest %s", __func__);
}
