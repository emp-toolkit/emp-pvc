#pragma once
#include <emp-tool/io/io_channel.h>
#include <stdio.h>
#include <unistd.h>
namespace emp {
class PipeIO : public IOChannel<PipeIO> {
private:
    int rd_, wt_;
      
public:
    int64_t scounter = 0;
    int64_t rcounter = 0;
    PipeIO(int rd, int wt) : rd_(rd), wt_(wt) {
    }

    ~PipeIO() {
        close(rd_);
        close(wt_);
    }

    void send_data(const void *data, int len) {
        const uint8_t *ptr = (const uint8_t *)data;
        scounter += len;
        do {
            int b = write(wt_, ptr, len);
            if (b == 0)
                break;
            ptr += b;
            len -= b;
        } while (len > 0);
    }

    void recv_data(void *data, int len) {
        uint8_t *ptr = (uint8_t *)data;
        rcounter += len;
        do {
            int b = read(rd_, ptr, len);
            if (b == 0) break;
            ptr += b;
            len -= b;
        } while (len > 0);
    }

    void flush() {}
    
    void clear() {}
};

void destory_pipe(std::pair<PipeIO *, PipeIO *> &pipe) {
    if (pipe.first) delete pipe.first;
    if (pipe.second) delete pipe.second;
}

std::pair<PipeIO *, PipeIO *> create_pipe(bool *ok) {
    int fd[2][2];
    if (pipe(fd[0]) == -1) {
        if (ok) *ok = false;
        return {nullptr, nullptr};
    }
    if (pipe(fd[1]) == -1) {
        close(fd[0][0]);
        close(fd[0][1]);
        if (ok) *ok = false;
        return {nullptr, nullptr};
    }

    auto p1 = new PipeIO(fd[0][0], fd[1][1]);
    auto p2 = new PipeIO(fd[1][0], fd[0][1]);
    if (ok) *ok = true;
    return {p1, p2};
}
}

