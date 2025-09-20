#include "Logger.h"
#include <chrono>
#include <ctime>
#include <iostream>

Logger::Logger(const std::string &filename) {
    ofs_.open(filename, std::ios::out | std::ios::app);
    if (!ofs_) {
        throw std::runtime_error("Failed to open log file");
    }
}

Logger::~Logger() {
    if (ofs_.is_open()) ofs_.close();
}

void Logger::log(const std::string &line) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    ofs_ << std::ctime(&t) << " : " << line << std::endl;
    ofs_.flush();
}
