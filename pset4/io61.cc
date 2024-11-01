#include "io61.hh"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <climits>
#include <cerrno>

// io61.cc
//    YOUR CODE HERE!


// io61_file
//    Data structure for io61 file wrappers. Add your own stuff.

struct io61_file {
    int fd = -1;     // file descriptor
    int mode;      // open mode (O_RDONLY or O_WRONLY)
    off_t tag; 
    off_t pos_tag;
    off_t end_tag;
    static constexpr off_t bufsize = 4096; //cache block size
    unsigned char cbuf[bufsize]; //cached data
    unsigned char* mmap_data = nullptr; // pointer to mapped data
    off_t mmap_size = 0; // size of mapped data
};


// io61_fdopen(fd, mode)
//    Returns a new io61_file for file descriptor `fd`. `mode` is either
//    O_RDONLY for a read-only file or O_WRONLY for a write-only file.
//    You need not support read/write files.

io61_file* io61_fdopen(int fd, int mode) {
    assert(fd >= 0);
    io61_file* f = new io61_file;
    f->fd = fd;
    f->mode = mode;
    f->tag = 0;
    f->end_tag = 0;
    f->pos_tag = 0;

    //if we are read only, we can set up the mmap
    if (mode == O_RDONLY) {
        // Get the file size
        struct stat s;
        if (fstat(fd, &s) == 0 && S_ISREG(s.st_mode)) {
            f->mmap_size = s.st_size;
            f->mmap_data = (unsigned char*) mmap(nullptr, f->mmap_size, PROT_READ, MAP_PRIVATE, fd, 0); //map when we can
            if (f->mmap_data == MAP_FAILED) { //if the map fails, set the struct data accordingly
                f->mmap_data = nullptr;
                f->mmap_size = 0;
            }
        }
    }

    return f;
}


// io61_close(f)
//    Closes the io61_file `f` and releases all its resources.

int io61_close(io61_file* f) {
    io61_flush(f);
    if (f->mmap_data) { //if f->mmap_data is not the nullptr, we can do this
        munmap(f->mmap_data, f->mmap_size);
    }
    int r = close(f->fd);
    delete f;
    return r;
}

// io61_fill returns -1 on error, otherwise returns non-negative n (n = 0 would imply EOF).
int io61_fill(io61_file* f) {
    if (f->mmap_data) {
        return 0; // no need to fill when using mmap
    }

    // check
    assert(f->tag <= f->pos_tag && f->pos_tag <= f->end_tag);
    assert(f->end_tag - f->pos_tag <= f->bufsize);

    f->tag = f->pos_tag = f->end_tag;
    // read
    ssize_t n = read(f->fd, f->cbuf, f->bufsize);
    if (n >= 0) {
        f->end_tag = f->tag + n;
    }
    else{
        return -1;
    }
    // rechecking because section notes told us to
    assert(f->tag <= f->pos_tag && f->pos_tag <= f->end_tag);
    assert(f->end_tag - f->pos_tag <= f->bufsize);
    
    return n;
}

// io61_readc(f)
//    Reads a single (unsigned) byte from `f` and returns it. Returns EOF,
//    which equals -1, on end of file or error.


int io61_readc(io61_file* f) {
    unsigned char ch; 
    ssize_t n = io61_read(f, &ch, 1); 
    if(n == 1){
        return ch;
    }
    else{
        return -1;
    }
}



// io61_read(f, buf, sz)
//    Reads up to `sz` bytes from `f` into `buf`. Returns the number of
//    bytes read on success. Returns 0 if end-of-file is encountered before
//    any bytes are read, and -1 if an error is encountered before any
//    bytes are read.

ssize_t io61_read(io61_file* f, unsigned char* buf, size_t sz) {
    if (f->mmap_data) {
        if (f->pos_tag >= f->mmap_size) {
            // EOF
            return 0;
        }
        size_t bytes_available = f->mmap_size - f->pos_tag; //the total number of bytes is the difference between the size of the mmap and the current position
        size_t bytes_to_copy = sz;
        if (bytes_to_copy > bytes_available) {
            bytes_to_copy = bytes_available;
        }
        memcpy(buf, f->mmap_data + f->pos_tag, bytes_to_copy);
        f->pos_tag += bytes_to_copy;
        return bytes_to_copy;
    } else {
        size_t nread = 0;
        while (nread < sz) {
            // Check if cache needs refilling
            if (f->pos_tag >= f->end_tag) {
                int n = io61_fill(f);
                if (n == -1) { // if fill fails, figure out if we are at EOF or if another error occurred
                    return -1;
                }
                if (n == 0) {
                    break;
                }
            }
            assert(f->tag <= f->end_tag);
            assert(f->pos_tag >= f->tag);
            //calculate how much we can/need to read from the cache

            size_t bytes_to_copy = f->end_tag - f->pos_tag;
            if(bytes_to_copy > sz - nread){
                bytes_to_copy = sz - nread;
            }
            // Copy from cache to the output buffer

            memcpy(&buf[nread], &f->cbuf[f->pos_tag - f->tag], bytes_to_copy);
            // Update position pointer, update the value of nread.
            f->pos_tag += bytes_to_copy;
            nread += bytes_to_copy;
        }

        // Return the number of bytes read, which should be sz 
        if (nread != 0 || sz == 0 || errno == 0) {
            return nread;
        }
        else {
            return -1;
        }
    }
}

// io61_writec(f)
//    Write a single character `c` to `f` (converted to unsigned char).
//    Returns 0 on success and -1 on error.

int io61_writec(io61_file* f, int c) {
    unsigned char ch = c;
    ssize_t nw = io61_write(f, &ch, 1); //write a single character lol
    if (nw == 1) {
        return 0;
    } else {
        return -1;
    }
}


// io61_write(f, buf, sz)
//    Writes `sz` characters from `buf` to `f`. Returns `sz` on success.
//    Can write fewer than `sz` characters when there is an error, such as
//    a drive running out of space. In this case io61_write returns the
//    number of characters written, or -1 if no characters were written
//    before the error occurred.

ssize_t io61_write(io61_file* f, const unsigned char* buf, size_t sz) {
    size_t nwritten = 0;
    while(nwritten < sz){
        if(f->pos_tag == f->tag + f->bufsize){ //if the current pos_tag is equal to the typical spot for the end_tag, flush
            int n = io61_flush(f);
            if (n < 0){
                break;
            }
        }
        size_t bytes_to_copy = f->tag + f->bufsize - f->pos_tag; //calculate the number of bytes to copy from our cache to buffer
        if(bytes_to_copy > sz - nwritten){ //if we can fit sz characters into our cache, then do that!
            bytes_to_copy = sz - nwritten;
        }

        memcpy(&f->cbuf[f->pos_tag - f->tag], buf + nwritten, bytes_to_copy);

        f->pos_tag += bytes_to_copy; //update pos_tag, end_tag
        f->end_tag += bytes_to_copy;
        nwritten += bytes_to_copy;
    }
    return nwritten;
}


// io61_flush(f)
//    If `f` was opened write-only, `io61_flush(f)` forces a write of any
//    cached data written to `f`. Returns 0 on success; returns -1 if an error
//    is encountered before all cached data was written.
//
//    If `f` was opened read-only, `io61_flush(f)` returns 0. It may also
//    drop any data cached for reading.

int io61_flush(io61_file* f) {
    if (f->mode == O_RDONLY) { //if read only, return 0.
        return 0;
    }
    off_t nflushed = 0;
    while (f->tag + nflushed < f->end_tag) {
        ssize_t n = write(f->fd, f->cbuf + nflushed, f->end_tag - f->tag - nflushed); //flush!!!
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            } else {
                return -1;
            }
        } else {
            nflushed += n; //increment our total number of flushed
        }
    }
    assert(f->tag + nflushed == f->end_tag); //we should have flushed the entire cache
    f->tag = f->end_tag;
        
    return 0;
}



// io61_seek(f, off)
//    Changes the file pointer for file `f` to `off` bytes into the file.
//    Returns 0 on success and -1 on failure.

int io61_seek(io61_file* f, off_t off) {
    if (f->mmap_data) {
        if (off >= 0 && off <= (off_t) f->mmap_size) { //if the offset is within the mmap size, simply change the pos_tag
            f->pos_tag = off;
            return 0;
        }
        } else {
        assert(f->mode == O_RDONLY || f->mode == O_WRONLY);
        if(f->mode == O_RDONLY){
            if (f->tag <= off && off <= f->end_tag) {
                f->pos_tag = off;
            }
            off_t begincache = (off / f->bufsize) * f->bufsize; //truncate off to align with bufsize
            off_t r = lseek(f->fd, begincache, SEEK_SET); //set the file pointer to the aligned position
            if (r == -1) {
                return -1;
            }
            ssize_t n = read(f->fd, f->cbuf, f->bufsize); //set the cache
            f->tag = begincache;
            f->end_tag = begincache + n;
            f->pos_tag = off;
        } else { //otherwise, if it's write only, flush and set our file point
            io61_flush(f);
            off_t r = lseek(f->fd, off, SEEK_SET);
            if (r == -1) {
                return -1;
            }
            f->tag = r;
            f->pos_tag = r;
            f->end_tag = r;
        }
    }
    return 0;
}






// You shouldn't need to change these functions.

// io61_open_check(filename, mode)
//    Opens the file corresponding to `filename` and returns its io61_file.
//    If `!filename`, returns either the standard input or the
//    standard output, depending on `mode`. Exits with an error message if
//    `filename != nullptr` and the named file cannot be opened.

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


// io61_fileno(f)
//    Returns the file descriptor associated with `f`.

int io61_fileno(io61_file* f) {
    return f->fd;
}


// io61_filesize(f)
//    Returns the size of `f` in bytes. Returns -1 if `f` does not have a
//    well-defined size (for instance, if it is a pipe).

off_t io61_filesize(io61_file* f) {
    struct stat s;
    int r = fstat(f->fd, &s);
    if (r >= 0 && S_ISREG(s.st_mode)) {
        return s.st_size;
    } else {
        return -1;
    }
}
