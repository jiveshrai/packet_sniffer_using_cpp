#pragma once
#include <string>
#include <fstream>
#include <mutex>

class Logger {
public:
    explicit Logger(const std::string &filename);
    ~Logger();

    void log(const std::string &line);

private:
    std::ofstream ofs_;
    std::mutex mtx_;
};
