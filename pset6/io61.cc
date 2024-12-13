#include "io61.hh"
#include <climits>
#include <cerrno>
#include <vector>
#include <mutex>
#include <thread>
#include <shared_mutex>
#include <condition_variable>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cassert>
#include <cstring>
#include <algorithm>
// io61.cc
//    YOUR CODE HERE!

struct LockRange { //struct to keep track of regions + owner ids
    off_t off;
    off_t len;
    std::thread::id owner;
};

// io61_file
//    Data structure for io61 file wrappers.
//

struct io61_file {
    int fd = -1;     // file descriptor
    int mode;        // O_RDONLY, O_WRONLY, or O_RDWR
    bool seekable;   // is this file seekable?

    static constexpr off_t cbufsz = 8192;
    unsigned char cbuf[cbufsz];
    off_t tag;       // offset of first character in `cbuf`
    off_t pos_tag;   // next offset to read or write (non-positioned mode)
    off_t end_tag;   // offset one past last valid character in `cbuf`

    std::atomic<bool> dirty = false;
    bool positioned = false;  // is cache in positioned mode?

    std::mutex mtx; //mutex to make sure that multiple threads don't modify shared states at the same time
    std::condition_variable_any cv; //conditional variable for io61_lock().
    std::vector<LockRange> locks; //vector that keeps track of all of the different regions
};
//helper function that figures out whether or not two regions are overlapping
//returns true when there's no overlap, and false when there is
static bool no_overlap(off_t off1, off_t len1, off_t off2, off_t len2) { 
    return (off1 + len1 <= off2 || off2 + len2 <= off1);
}

//helper function that determines whether or not there's an issue with the new lock we are trying to make

static bool some_issue(io61_file* f, off_t off, off_t len) {
    for (auto& region : f->locks) {
        if (!no_overlap(off,len, region.off,region.len) && std::this_thread::get_id() != region.owner) {
            //if we have an overlap with a region locked by a different owner, return true
            return true; 
        }
    }
    //after iterating through if there are no errors, return false
    return false;
}

// Forward declarations of helper functions that assume the mutex is already held
static int io61_fill_nolock(io61_file* f);
static int io61_flush_dirty_nolock(io61_file* f);
static int io61_flush_dirty_positioned_nolock(io61_file* f);
static int io61_flush_clean_nolock(io61_file* f);
static int io61_pfill_nolock(io61_file* f, off_t off);

// io61_fdopen(fd, mode)
io61_file* io61_fdopen(int fd, int mode) {
    assert(fd >= 0);
    assert((mode & O_APPEND) == 0);
    io61_file* f = new io61_file;
    f->fd = fd;
    f->mode = mode & O_ACCMODE;
    off_t off = lseek(fd, 0, SEEK_CUR);
    if (off != -1) {
        f->seekable = true;
        f->tag = f->pos_tag = f->end_tag = off;
    } else {
        f->seekable = false;
        f->tag = f->pos_tag = f->end_tag = 0;
    }
    f->dirty = f->positioned = false;
    return f;
}

// io61_close(f)
int io61_close(io61_file* f) {
    {
        std::unique_lock<std::mutex> lk(f->mtx); //locks the function from being accessed by multiple threads
        if (f->dirty) {
            if (f->positioned) {
                io61_flush_dirty_positioned_nolock(f);
            } else {
                io61_flush_dirty_nolock(f);
            }
        } else {
            io61_flush_clean_nolock(f);
        }
    }
    int r = close(f->fd);
    delete f;
    return r;
}

// io61_readc(f)
int io61_readc(io61_file* f) {
    std::unique_lock<std::mutex> lk(f->mtx); //locks the function from being accessed by multiple threads
    if (f->positioned) {
        // Switch out of positioned mode
        if (f->dirty) {
            if (io61_flush_dirty_positioned_nolock(f) == -1) return -1;
        } else {
            if (io61_flush_clean_nolock(f) == -1) return -1;
        }
        f->positioned = false;
    }
    if (f->pos_tag == f->end_tag) {
        if (io61_fill_nolock(f) == -1) {
            return -1;
        }
        if (f->pos_tag == f->end_tag) {
            return -1;
        }
    }
    unsigned char ch = f->cbuf[f->pos_tag - f->tag];
    ++f->pos_tag;
    return ch;
}

// io61_read(f, buf, sz)
ssize_t io61_read(io61_file* f, unsigned char* buf, size_t sz) {
    std::unique_lock<std::mutex> lk(f->mtx); //locks the function from being accessed by multiple threads
    if (f->positioned) {
        if (f->dirty) {
            if (io61_flush_dirty_positioned_nolock(f) == -1) return -1;
        } else {
            if (io61_flush_clean_nolock(f) == -1) return -1;
        }
        f->positioned = false;
    }
    size_t nread = 0;
    while (nread != sz) {
        if (f->pos_tag == f->end_tag) {
            int r = io61_fill_nolock(f);
            if (r == -1 && nread == 0) {
                return -1;
            } else if (f->pos_tag == f->end_tag) {
                break;
            }
        }
        size_t nleft = f->end_tag - f->pos_tag;
        size_t ncopy = std::min(sz - nread, nleft);
        memcpy(&buf[nread], &f->cbuf[f->pos_tag - f->tag], ncopy);
        nread += ncopy;
        f->pos_tag += ncopy;
    }
    return nread;
}

// io61_writec(f)
int io61_writec(io61_file* f, int c) {
    std::unique_lock<std::mutex> lk(f->mtx); //locks the function from being accessed by multiple threads
    if (f->positioned) {
        if (f->dirty) {
            if (io61_flush_dirty_positioned_nolock(f) == -1) return -1;
        } else {
            if (io61_flush_clean_nolock(f) == -1) return -1;
        }
        f->positioned = false;
    }
    if (f->pos_tag == f->tag + f->cbufsz) {
        if (f->dirty) {
            if (io61_flush_dirty_nolock(f) == -1) return -1;
        } else {
            if (io61_flush_clean_nolock(f) == -1) return -1;
        }
    }
    f->cbuf[f->pos_tag - f->tag] = c;
    ++f->pos_tag;
    ++f->end_tag;
    f->dirty = true;
    return 0;
}

// io61_write(f, buf, sz)
ssize_t io61_write(io61_file* f, const unsigned char* buf, size_t sz) {
    std::unique_lock<std::mutex> lk(f->mtx); //locks the function from being accessed by multiple threads
    if (f->positioned) {
        if (f->dirty) {
            if (io61_flush_dirty_positioned_nolock(f) == -1) return -1;
        } else {
            if (io61_flush_clean_nolock(f) == -1) return -1;
        }
        f->positioned = false;
    }
    size_t nwritten = 0;
    while (nwritten != sz) {
        if (f->end_tag == f->tag + f->cbufsz) {
            if (f->dirty) {
                int r = io61_flush_dirty_nolock(f);
                if (r == -1 && nwritten == 0) {
                    return -1;
                } else if (r == -1) {
                    break;
                }
            } else {
                if (io61_flush_clean_nolock(f) == -1 && nwritten == 0) {
                    return -1;
                }
            }
        }
        size_t nleft = f->tag + f->cbufsz - f->pos_tag;
        size_t ncopy = std::min(sz - nwritten, nleft);
        memcpy(&f->cbuf[f->pos_tag - f->tag], &buf[nwritten], ncopy);
        f->pos_tag += ncopy;
        f->end_tag += ncopy;
        f->dirty = true;
        nwritten += ncopy;
    }
    return nwritten;
}

// io61_flush(f)
int io61_flush(io61_file* f) {
    std::unique_lock<std::mutex> lk(f->mtx); //locks the function from being accessed by multiple threads
    if (f->dirty && f->positioned) {
        return io61_flush_dirty_positioned_nolock(f);
    } else if (f->dirty) {
        return io61_flush_dirty_nolock(f);
    } else {
        return io61_flush_clean_nolock(f);
    }
}

// io61_seek(f, off)
int io61_seek(io61_file* f, off_t off) {
    std::unique_lock<std::mutex> lk(f->mtx); //locks the function from being accessed by multiple threads
    int r;
    if (f->dirty && f->positioned) {
        r = io61_flush_dirty_positioned_nolock(f);
    } else if (f->dirty) {
        r = io61_flush_dirty_nolock(f);
    } else {
        r = io61_flush_clean_nolock(f);
    }
    if (r == -1) {
        return -1;
    }
    off_t roff = lseek(f->fd, off, SEEK_SET);
    if (roff == -1) {
        return -1;
    }
    f->tag = f->pos_tag = f->end_tag = off;
    f->positioned = false;
    return 0;
}

// io61_pread
ssize_t io61_pread(io61_file* f, unsigned char* buf, size_t sz, off_t off) {
    std::unique_lock<std::mutex> lk(f->mtx); //locks the function from being accessed by multiple threads
    if (!f->positioned || off < f->tag || off >= f->end_tag) {
        if (io61_pfill_nolock(f, off) == -1) {
            return -1;
        }
    }
    size_t nleft = f->end_tag - off;
    size_t ncopy = std::min(sz, nleft);
    memcpy(buf, &f->cbuf[off - f->tag], ncopy);
    return ncopy;
}

// io61_pwrite
ssize_t io61_pwrite(io61_file* f, const unsigned char* buf, size_t sz, off_t off) {
    std::unique_lock<std::mutex> lk(f->mtx); //locks the function from being accessed by multiple threads
    if (!f->positioned || off < f->tag || off >= f->end_tag) {
        if (io61_pfill_nolock(f, off) == -1) {
            return -1;
        }
    }
    size_t nleft = f->end_tag - off;
    size_t ncopy = std::min(sz, nleft);
    memcpy(&f->cbuf[off - f->tag], buf, ncopy);
    f->dirty = true;
    return ncopy;
}

// io61_try_lock
int io61_try_lock(io61_file* f, off_t off, off_t len, int locktype) {
    assert(locktype == LOCK_EX);
    std::unique_lock<std::mutex> lock(f->mtx, std::try_to_lock);
    if (!lock.owns_lock()) { //unique lock ensures that we don't block other threads.- if there's an issue and we couldn't lock, return -1.
        return -1;
    }
    if (some_issue(f, off, len)) { //if there's an issue, return -1;
        return -1;
    }
    f->locks.emplace_back(LockRange{off, len, std::this_thread::get_id()}); //place the locked region in our vector of LockRange objects
    return 0;
}

// io61_lock
int io61_lock(io61_file* f, off_t off, off_t len, int locktype) {
    assert(locktype == LOCK_EX || locktype == LOCK_SH);
    std::unique_lock<std::mutex> lock(f->mtx);
    f->cv.wait(lock, [&f, off, len]() { //use the conditional variable to keep trying to lock
        return !some_issue(f, off, len); //if there's some issue, continue to wait
    });
    f->locks.emplace_back(LockRange{off, len, std::this_thread::get_id()}); //place the locked region in our vector of LockRange objects
    return 0;
}

// io61_unlock
int io61_unlock(io61_file* f, off_t off, off_t len) {
    std::unique_lock<std::mutex> lock(f->mtx);
    std::thread::id current_owner = std::this_thread::get_id();
    //looks through the vector of LockRange objects, if we can find one that matches our criteria, then continue
    //if no LockRange object exists, it = f->locks.end(), so we will return -1.
    auto it = std::find_if(f->locks.begin(), f->locks.end(), [&](const LockRange& lr) {return lr.off == off && lr.len == len && lr.owner == current_owner;}); 
    if(it != f->locks.end()){
        f->locks.erase(it);
        f->cv.notify_all();
        return 0;
    } else {
        return -1;
    }
}

// Helper functions that assume lock is held
static int io61_fill_nolock(io61_file* f) {
    assert(f->tag == f->end_tag && f->pos_tag == f->end_tag);
    ssize_t nr;
    while (true) {
        nr = read(f->fd, f->cbuf, f->cbufsz);
        if (nr >= 0) {
            break;
        } else if (errno != EINTR && errno != EAGAIN) {
            return -1;
        }
    }
    f->end_tag += nr;
    return 0;
}

static int io61_flush_dirty_nolock(io61_file* f) {
    off_t flush_tag = f->tag;
    while (flush_tag != f->end_tag) {
        ssize_t nw = write(f->fd, &f->cbuf[flush_tag - f->tag],
                           f->end_tag - flush_tag);
        if (nw >= 0) {
            flush_tag += nw;
        } else if (errno != EINTR && errno != EINVAL) {
            return -1;
        }
    }
    f->dirty = false;
    f->tag = f->pos_tag = f->end_tag;
    return 0;
}

static int io61_flush_dirty_positioned_nolock(io61_file* f) {
    off_t flush_tag = f->tag;
    while (flush_tag != f->end_tag) {
        ssize_t nw = pwrite(f->fd, &f->cbuf[flush_tag - f->tag],
                            f->end_tag - flush_tag, flush_tag);
        if (nw >= 0) {
            flush_tag += nw;
        } else if (errno != EINTR && errno != EINVAL) {
            return -1;
        }
    }
    f->dirty = false;
    return 0;
}

static int io61_flush_clean_nolock(io61_file* f) {
    if (!f->positioned && f->seekable) {
        if (lseek(f->fd, f->pos_tag, SEEK_SET) == -1) {
            return -1;
        }
        f->tag = f->end_tag = f->pos_tag;
    }
    return 0;
}

static int io61_pfill_nolock(io61_file* f, off_t off) {
    assert(f->mode == O_RDWR);
    if (f->dirty) {
        if (f->positioned) {
            if (io61_flush_dirty_positioned_nolock(f) == -1) return -1;
        } else {
            if (io61_flush_dirty_nolock(f) == -1) return -1;
        }
    } else {
        if (io61_flush_clean_nolock(f) == -1) return -1;
    }

    off = off - (off % 8192);
    ssize_t nr = pread(f->fd, f->cbuf, f->cbufsz, off);
    if (nr == -1) {
        return -1;
    }
    f->tag = off;
    f->end_tag = off + nr;
    f->positioned = true;
    return 0;
}

// io61_open_check, io61_fileno, io61_filesize unchanged

io61_file* io61_open_check(const char* filename, int mode) {
    int fd;
    if (filename) {
        fd = open(filename, mode, 0666);
    } else if ((mode & O_ACCMODE) == O_RDONLY) {
        fd = STDIN_FILENO;
    } else {
        fd = STDOUT_FILENO;
    }
    if (fd < 0) {
        fprintf(stderr, "%s: %s\n", filename, strerror(errno));
        exit(1);
    }
    return io61_fdopen(fd, mode & O_ACCMODE);
}

int io61_fileno(io61_file* f) {
    return f->fd;
}

off_t io61_filesize(io61_file* f) {
    struct stat s;
    int r = fstat(f->fd, &s);
    if (r >= 0 && S_ISREG(s.st_mode)) {
        return s.st_size;
    } else {
        return -1;
    }
}
