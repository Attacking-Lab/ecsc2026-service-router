#include <zephyr/fatal.h>
#include <zephyr/logging/log.h>

#define K_ERR_SUCCESS 255

LOG_MODULE_REGISTER(test_selftest, CONFIG_SELFTEST_LOG_LEVEL);


#define RUN_TEST(name) \
    LOG_INF("\x1b[1m%s\x1b[0m", #name); \
    extern void name(void); \
    name();

#define SKIP_TEST(name) \
    LOG_INF("\x1b[1m%s\x1b[0m (skipped)", #name);

#define RUN_IF(cfg, name) \
    do { \
        COND_CODE_1(cfg, (RUN_TEST(name)), (SKIP_TEST(name))) \
    } while (0)


void run_selftests() {
    RUN_IF(CONFIG_SELFTEST_ATM_NETDEV, test_atm_netdev);
    LOG_INF("\x1b[1;32mAll enabled self-tests completed.\x1b[0m");
    k_fatal_halt(K_ERR_SUCCESS);
}
