// SPDX-License-Identifier: MIT
#include <algorithm>
#include <atomic>
#include <cmath>
#include <iostream>
#include <numeric>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

static thread_local unsigned local = 17;

int main()
{
    std::vector<double> values{3.5, 1.25, 2.75, 0.5};
    std::sort(values.begin(), values.end());
    if (std::accumulate(values.begin(), values.end(), 0.0) != 8.0)
        return 10;
    try {
        throw std::runtime_error("standard-a53-exception");
    } catch (const std::exception &error) {
        if (std::string(error.what()) != "standard-a53-exception")
            return 11;
    }
    volatile double two = 2.0;
    if (std::abs(std::sqrt(two) - 1.4142135623730951) > 1e-14)
        return 12;
    std::atomic<unsigned long long> count{0};
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < 4; i++) {
        threads.emplace_back([&count, i] {
            if (local != 17)
                std::terminate();
            local = i + 200;
            for (unsigned j = 0; j < 10000; j++)
                count.fetch_add(1);
            if (local != i + 200)
                std::terminate();
        });
    }
    for (auto &thread : threads)
        thread.join();
    if (count != 40000 || local != 17)
        return 13;
    std::cout << "STANDARD_A53_CXX_PASS stl=ok exception=ok sqrt=ok threads=4 atomic64=40000 tls=ok\n";
}
