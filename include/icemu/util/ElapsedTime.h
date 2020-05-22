#ifndef ICEMU_UTIL_ELAPSED_TIME_H_
#define ICEMU_UTIL_ELAPSED_TIME_H_

#include <chrono>

class ElapsedTime {
    private:
        std::chrono::high_resolution_clock::time_point start_;
        std::chrono::high_resolution_clock::time_point end_;

    public:
        inline void start() {
            start_ = std::chrono::high_resolution_clock::now();
        }

        inline void stop() {
            end_ = std::chrono::high_resolution_clock::now();
        }

        inline long get_ns() {
            return std::chrono::duration_cast<std::chrono::nanoseconds>(end_ - start_).count();
        }

        inline double get_us() {
            auto ns = get_ns();
            return (double)ns / 1000.0;
        }

        inline double get_ms() {
            auto us = get_us();
            return (double)us / 1000.0;
        }

        inline double get_s() {
            auto ms = get_ms();
            return (double)ms / 1000.0;
        }
};

#endif /* ICEMU_UTIL_ELAPSED_TIME_H_ */
