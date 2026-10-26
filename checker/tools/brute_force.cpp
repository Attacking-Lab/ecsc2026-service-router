/*

recover an F5 record key from a GET response

The service derives the AES-128 record key with `f5cs_generate_key()` (see
`meta/zephyr/app/src/f5.c`): a 32-bit xorshift seeded with `k_uptime_get_32()`,
i.e. the device uptime in milliseconds.  That is at most 32 bits of entropy, and
in practice far less -- a device that has been up for eight hours only has ~2^25
plausible seeds.

A GET response hands us `ct` and `mac = CMAC-AES128(ct || nonce, key)[:7]`, which
is enough to recognise the right key.  So: enumerate seeds, derive the key,
compute the truncated CMAC, compare.  7 bytes of tag over a 32-bit seed space
means a hit is the key, not a collision.

    g++ -std=c++20 -O3 -march=native -pthread brute_force.cpp -o brute_force
    ./brute_force <ct-hex> <nonce-hex> <mac-hex>

Needs AES-NI (any x86-64 from ~2010 onwards); `-march=native` or `-maes -mssse3`.

*/

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <immintrin.h>

#ifdef __unix__
#include <unistd.h> // for isatty()
#endif

#if !defined(__AES__) || !defined(__SSSE3__)
#error "need AES-NI and SSSE3; compile with -march=native (or -maes -mssse3)"
#endif

namespace {

constexpr size_t MAC_SIZE = 7;  // f5_mac_t
constexpr size_t KEY_SIZE = 16; // f5_key_t

constexpr uint64_t SEED_SPACE = 1ull << 32;
constexpr uint64_t CHUNK = 1ull << 16;

/* Number of candidate keys kept in flight.  AES-NI is pipelined (aesenc has a
 * throughput of one per cycle but a latency of three to four), so the CMAC of a
 * single candidate leaves the unit mostly idle. */
constexpr size_t WAYS = 8;

////////////////////////////////////////////////////////////////// hex

class not_hex : public std::domain_error { public: not_hex(std::string const& s) : std::domain_error(s) { } };

std::vector<uint8_t> unhex(std::string const& s)
{
    if (s.length() % 2 || !std::all_of(s.begin(), s.end(), [](unsigned char c) { return isxdigit(c); }))
        throw not_hex("could not parse hex: <" + s + ">");
    std::vector<uint8_t> r;
    r.reserve(s.length() / 2);
    for (size_t i = 0; i < s.length(); i += 2)
        r.push_back((uint8_t) std::stoi(s.substr(i, 2), nullptr, 16));
    return r;
}

template <typename T>
std::string hex(T const& s)
{
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c: s) ss << std::setw(2) << (unsigned) c;
    return ss.str();
}

////////////////////////////////////////////////////////////////// AES-128

inline __m128i aes_expand_step(__m128i key, __m128i generated)
{
    generated = _mm_shuffle_epi32(generated, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, generated);
}

/* WAYS independent AES-128 key schedules, interleaved round by round. */
template <size_t N>
struct aes128_batch
{
    __m128i rk[11][N];

    void set_keys(__m128i const (&keys)[N])
    {
        __m128i k[N];
        for (size_t j = 0; j < N; ++j) rk[0][j] = k[j] = keys[j];

#define ROUND(i, rcon) \
        for (size_t j = 0; j < N; ++j) \
            rk[i][j] = k[j] = aes_expand_step(k[j], _mm_aeskeygenassist_si128(k[j], rcon));

        ROUND( 1, 0x01) ROUND( 2, 0x02) ROUND( 3, 0x04) ROUND( 4, 0x08) ROUND( 5, 0x10)
        ROUND( 6, 0x20) ROUND( 7, 0x40) ROUND( 8, 0x80) ROUND( 9, 0x1b) ROUND(10, 0x36)
#undef ROUND
    }

    void encrypt(__m128i (&block)[N]) const
    {
        for (size_t j = 0; j < N; ++j) block[j] = _mm_xor_si128(block[j], rk[0][j]);
        for (size_t r = 1; r < 10; ++r)
            for (size_t j = 0; j < N; ++j) block[j] = _mm_aesenc_si128(block[j], rk[r][j]);
        for (size_t j = 0; j < N; ++j) block[j] = _mm_aesenclast_si128(block[j], rk[10][j]);
    }
};

////////////////////////////////////////////////////////////////// CMAC

/* Doubling in GF(2^128), on the big-endian value held in `v`.  Byte-swapping
 * first puts the number where the shift instructions expect it. */
inline __m128i gf_double(__m128i v)
{
    __m128i const bswap = _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);

    __m128i x = _mm_shuffle_epi8(v, bswap);
    __m128i carry = _mm_slli_si128(_mm_srli_epi64(x, 63), 8);        // low half's top bit -> high half
    __m128i msb = _mm_srai_epi32(_mm_shuffle_epi32(x, _MM_SHUFFLE(3, 3, 3, 3)), 31);
    x = _mm_or_si128(_mm_slli_epi64(x, 1), carry);
    x = _mm_xor_si128(x, _mm_and_si128(msb, _mm_set_epi64x(0, 0x87)));
    return _mm_shuffle_epi8(x, bswap);
}

/* The message is the same for every candidate, so pad it once. */
struct message
{
    std::vector<uint8_t> padded;
    bool complete;  // last block is a full one, i.e. use K1 rather than K2

    explicit message(std::vector<uint8_t> data) : padded(std::move(data))
    {
        complete = !padded.empty() && padded.size() % 16 == 0;
        if (!complete) {
            padded.push_back(0x80);
            padded.resize((padded.size() + 15) / 16 * 16, 0x00);
        }
    }

    size_t blocks() const { return padded.size() / 16; }
    __m128i block(size_t i) const { return _mm_loadu_si128((__m128i const *) &padded[16 * i]); }
};

template <size_t N>
inline void cmac(aes128_batch<N> const& ctx, message const& msg, __m128i (&tag)[N])
{
    __m128i subkey[N];
    for (size_t j = 0; j < N; ++j) subkey[j] = _mm_setzero_si128();
    ctx.encrypt(subkey);                                             // L = E_K(0)
    for (size_t j = 0; j < N; ++j) {
        subkey[j] = gf_double(subkey[j]);                            // K1
        if (!msg.complete) subkey[j] = gf_double(subkey[j]);         // K2
    }

    for (size_t j = 0; j < N; ++j) tag[j] = _mm_setzero_si128();
    for (size_t i = 0; i + 1 < msg.blocks(); ++i) {
        __m128i const m = msg.block(i);
        for (size_t j = 0; j < N; ++j) tag[j] = _mm_xor_si128(tag[j], m);
        ctx.encrypt(tag);
    }
    __m128i const last = msg.block(msg.blocks() - 1);
    for (size_t j = 0; j < N; ++j)
        tag[j] = _mm_xor_si128(tag[j], _mm_xor_si128(last, subkey[j]));
    ctx.encrypt(tag);
}

////////////////////////////////////////////////////////////////// the actual search

/* `f5cs_generate_key()`: xorshift32, filling the key from the back. */
inline __m128i derive_key(uint32_t seed)
{
    alignas(16) uint8_t key[KEY_SIZE];
    uint32_t s = seed;
    for (size_t i = KEY_SIZE; i-- > 0; ) {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        key[i] = (uint8_t) s;
    }
    return _mm_load_si128((__m128i const *) key);
}

unsigned num_threads = std::max(1u, std::thread::hardware_concurrency());

std::atomic<bool> found {false};
std::atomic<uint32_t> solution {0};
std::atomic<uint64_t> cursor {0};
std::atomic<uint64_t> tried {0};

/* The tag's first MAC_SIZE bytes, as they sit in the low half of an xmm. */
constexpr uint64_t TAG_MASK = (1ull << (8 * MAC_SIZE)) - 1;

void brute(message const& msg, uint64_t target, uint64_t begin, uint64_t end)
{
    aes128_batch<WAYS> ctx;
    __m128i keys[WAYS], tag[WAYS];

    for (;;) {
        uint64_t base = begin + cursor.fetch_add(CHUNK, std::memory_order_relaxed);
        if (base >= end || found.load(std::memory_order_relaxed))
            break;
        uint64_t stop = std::min(base + CHUNK, end);

        for (uint64_t seed = base; seed < stop; seed += WAYS) {
            for (size_t j = 0; j < WAYS; ++j)
                keys[j] = derive_key((uint32_t) (seed + j));
            ctx.set_keys(keys);
            cmac(ctx, msg, tag);

            for (size_t j = 0; j < WAYS; ++j) {
                if (((uint64_t) _mm_cvtsi128_si64(tag[j]) & TAG_MASK) != target)
                    continue;
                if (seed + j < stop && !found.exchange(true))
                    solution = (uint32_t) (seed + j);
            }
        }

        tried.fetch_add(stop - base, std::memory_order_relaxed);
    }
}

/* Run one seed range across all threads, reporting progress on stderr. */
bool sweep(message const& msg, uint64_t target, uint64_t begin, uint64_t end, char const *what)
{
    bool const verbose =
#ifdef __unix__
        isatty(fileno(stderr));
#else
        false;
#endif

    uint64_t const total = end - begin;
    cursor = 0;
    tried = 0;

    std::cerr << "searching " << what << ": seeds " << begin << " .. " << end
              << " (" << total << " candidates) on " << num_threads << " threads" << std::endl;

    auto const started = std::chrono::steady_clock::now();

    std::vector<std::thread> threads;
    for (unsigned i = 0; i < num_threads; ++i)
        threads.emplace_back(brute, std::cref(msg), target, begin, end);

    while (true) {
        bool done = tried.load() >= total || found.load();
        if (verbose) {
            double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
            uint64_t n = tried.load();
            std::cerr << "\r\x1b[K" << (100.0 * n / total) << "% "
                      << "(" << (secs > 0 ? n / secs / 1e6 : 0) << " Mkeys/s)" << std::flush;
        }
        if (done) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    for (auto& t: threads) t.join();
    if (verbose) std::cerr << "\r\x1b[K" << std::flush;

    return found.load();
}

////////////////////////////////////////////////////////////////// self-test

bool self_test()
{
    // RFC 4493, AES-CMAC test vectors
    auto key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
    std::vector<std::pair<std::string, std::string>> const vectors {
        {"",
         "bb1d6929e95937287fa37d129b756746"},
        {"6bc1bee22e409f96e93d7e117393172a",
         "070a16b46b4d4144f79bdd9dd04a287c"},
        {"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
         "dfa66747de9ae63030ca32611497c827"},
        {"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
         "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
         "51f0bebf7e3b9d92fc49741779363cfe"},
    };

    bool ok = true;
    for (auto const& [msg_hex, tag_hex]: vectors) {
        aes128_batch<WAYS> ctx;
        __m128i keys[WAYS], tag[WAYS];
        for (size_t j = 0; j < WAYS; ++j) keys[j] = _mm_loadu_si128((__m128i const *) key.data());
        ctx.set_keys(keys);
        cmac(ctx, message(unhex(msg_hex)), tag);

        uint8_t got[16];
        _mm_storeu_si128((__m128i *) got, tag[0]);
        std::string got_hex = hex(std::vector<uint8_t>(got, got + 16));
        if (got_hex != tag_hex) {
            std::cerr << "FAIL for <" << msg_hex << ">:\n  want " << tag_hex << "\n  got  " << got_hex << std::endl;
            ok = false;
        }
    }

    // The key schedule, against a known AES-128 vector (FIPS-197 C.1)
    {
        aes128_batch<WAYS> ctx;
        __m128i keys[WAYS], block[WAYS];
        auto k = unhex("000102030405060708090a0b0c0d0e0f");
        auto p = unhex("00112233445566778899aabbccddeeff");
        for (size_t j = 0; j < WAYS; ++j) {
            keys[j] = _mm_loadu_si128((__m128i const *) k.data());
            block[j] = _mm_loadu_si128((__m128i const *) p.data());
        }
        ctx.set_keys(keys);
        ctx.encrypt(block);

        uint8_t got[16];
        _mm_storeu_si128((__m128i *) got, block[0]);
        std::string got_hex = hex(std::vector<uint8_t>(got, got + 16));
        if (got_hex != "69c4e0d86a7b0430d8cdb78070b4c55a") {
            std::cerr << "FAIL for AES-128-ECB: got " << got_hex << std::endl;
            ok = false;
        }
    }

    std::cerr << (ok ? "self-test passed" : "self-test FAILED") << std::endl;
    return ok;
}

[[noreturn]] void usage()
{
    std::cerr << "\n  \x1b[31musage\x1b[0m: brute_force [flags] <ct-hex> <nonce-hex> <mac-hex>\n"
              << "\nrecovers the AES-128 record key behind an F5 GET response\n"
              << "\nsupported flags:\n\n"
              << "  --hours H     hours of uptime to try first (default: 8, 0 to skip)\n"
              << "  --quick       stop after the plausible range instead of sweeping all 2^32 seeds\n"
              << "  --threads N   number of threads (default: #cpus)\n"
              << "  --self-test   check the CMAC implementation and exit\n"
              << "\nexample:\n\n"
              << "  ./brute_force $(xxd -p -c0 ct.bin) 1337 a1b2c3d4e5f607\n"
              << std::endl;
    exit(1);
}

} // namespace

int main(int argc, char **argv)
{
    std::vector<std::string> positional;
    double hours = 8.0;
    bool quick = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        auto value = [&]() -> std::string {
            if (i + 1 >= argc) usage();
            return argv[++i];
        };
        if (arg == "--self-test") return self_test() ? 0 : 1;
        else if (arg == "--quick") quick = true;
        else if (arg == "--hours") hours = std::stod(value());
        else if (arg == "--threads") num_threads = std::max(1, std::stoi(value()));
        else if (arg.rfind("--", 0) == 0) usage();
        else positional.push_back(arg);
    }

    if (positional.size() != 3) usage();

    message msg({});
    uint64_t target = 0;
    try {
        auto ct = unhex(positional[0]);
        auto nonce = unhex(positional[1]);
        auto mac = unhex(positional[2]);

        if (mac.size() < MAC_SIZE)
            throw std::domain_error("the MAC is " + std::to_string(MAC_SIZE) + " bytes, got " + std::to_string(mac.size()));
        for (size_t i = 0; i < MAC_SIZE; ++i)
            target |= (uint64_t) mac[i] << (8 * i);

        ct.insert(ct.end(), nonce.begin(), nonce.end());
        msg = message(std::move(ct));
    }
    catch (std::exception const& ex) {
        std::cerr << "\x1b[31m" << ex.what() << "\x1b[0m" << std::endl;
        exit(1);
    }

    /* The seed is `k_uptime_get_32()`, so small values are overwhelmingly likely:
     * start with an uptime of a few hours before committing to the whole space. */
    uint64_t plausible = std::min<uint64_t>(SEED_SPACE, (uint64_t) (hours * 3600.0 * 1000.0));
    plausible = (plausible + WAYS - 1) / WAYS * WAYS;
    if (!plausible && quick) usage();

    if (plausible)
        sweep(msg, target, 0, plausible, "plausible uptimes");
    if (!found && !quick && plausible < SEED_SPACE)
        sweep(msg, target, plausible, SEED_SPACE, "the remaining seed space");

    if (!found) {
        std::cerr << "\x1b[31mnot found\x1b[0m" << std::endl;
        exit(1);
    }

    uint32_t seed = solution;
    alignas(16) uint8_t key[KEY_SIZE];
    _mm_store_si128((__m128i *) key, derive_key(seed));

    std::cerr << "seed " << seed << " (uptime " << seed / 1000 << "." << std::setw(3) << std::setfill('0')
              << seed % 1000 << "s)" << std::endl;

    std::cout << hex(std::vector<uint8_t>(key, key + KEY_SIZE)) << std::flush;
#ifdef __unix__
    if (isatty(fileno(stdout))) std::cout << std::endl;
#endif
}
