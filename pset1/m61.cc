#include "m61.hh"
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <sys/mman.h>
#include <map>
#include <iostream>
#include <ostream>

struct m61_memory_buffer {
    char* buffer;
    size_t pos = 0;
    size_t size = 8 << 20; /* 8 MiB */

    m61_memory_buffer();
    ~m61_memory_buffer();
};
struct allocinfo{ //create a map from each pointer to the size and position of the memory it represents
    size_t sz;
    size_t pos;
};

static m61_memory_buffer default_buffer;
static unsigned long long ntotal = 0;
static unsigned long long nactive = 0;
static unsigned long long total_size = 0;
static unsigned long long nfail = 0;
static unsigned long long fail_size = 0;
static unsigned long long active_size = 0;
static uintptr_t heap_min = SIZE_MAX; // heap_min will only decrease with updates, so we initialize it using an arbitrarily large value
static uintptr_t heap_max = 0; // heap_max will only increase with updates, so we initialize it using an arbitrarily large value
static std::map<void*, allocinfo> mp;
static std::vector<void*> activeptrs;


m61_memory_buffer::m61_memory_buffer() {
    void* buf = mmap(nullptr,    // Place the buffer at a random address
        this->size,              // Buffer should be 8 MiB big
        PROT_WRITE,              // We want to read and write the buffer
        MAP_ANON | MAP_PRIVATE, -1, 0);
                                 // We want memory freshly allocated by the OS
    assert(buf != MAP_FAILED);
    this->buffer = (char*) buf;
}

m61_memory_buffer::~m61_memory_buffer() {
    munmap(this->buffer, this->size);
}

void resize() { //shift all of the allocations down in order to ensure that we don't have needless gaps in our memory allocation
    size_t temp = 0;
    for (auto& pair : mp) {
        pair.second.pos = temp; //
        temp += pair.second.sz; //update temp to track used size, so the pointer is always at the next available memory allocation position
    }
    heap_max = temp; //update heap_max to the new end of the heap
    
    default_buffer.pos = heap_max;
}

/// m61_malloc(sz, file, line)
///    Returns a pointer to `sz` bytes of freshly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc may
///    return either `nullptr` or a pointer to a unique allocation.
///    The allocation request was made at source code location `file`:`line`.

void* m61_malloc(size_t sz, const char* file, int line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    // Your code here.
    if(sz > default_buffer.size - default_buffer.pos) { //only resize when we can't fit something
    resize(); 
}

    if (sz > default_buffer.size - heap_max) { //if resizing still doesn't fit it, then return the nullptr
        // Not enough space left in default buffer for allocation
        // The rearrangement of the inequality ensures that default_buffer.size - default_buffer.pos never overflows, because default_buff.pos < default_buffer.size by construction.
        ++nfail; // Increase the fail counter by 2
        fail_size = fail_size + sz; // Increase the fail size by the size of the failed allocation
        return nullptr;
    }

    ++ntotal; // If the allocated memory fits, then add one to the total number of memory allocations
    ++nactive; // Add one to the number of active allocations
    total_size = total_size + sz; // Add the size of the allocation to the total size allocation (not just active)
    active_size = active_size + sz;
    size_t aligned_sz = sz + (16 - (sz % 16)) % 16; // Adjusted sizing to ensure that the default_buffer.pos is always a multiple of 16 by rounding sz up to the nearest  of 16. 

    // Otherwise there is enough space; claim the next `sz` bytes

    void* ptr = &default_buffer.buffer[default_buffer.pos];
    mp[ptr] = {sz, default_buffer.pos};

    uintptr_t ptr_as_uint = (uintptr_t) ptr; // Cast ptr as an unsigned int pointer in order to compare it to heap_min/max
    if(ptr_as_uint < heap_min){
        heap_min = ptr_as_uint; // update heap_min using ptr: if it is less than our heap_min value, then we want to replace it with the smaller pointer.
    }
    if(ptr_as_uint + sz > heap_max){
        heap_max = sz + ptr_as_uint; // We are interested in the last address of a pointer, so we have to update it every time we allocate memory such that the end of the memory is larger than the current heap_max
    }
    default_buffer.pos += aligned_sz; // Use the aligned size to update the buffer position
    

    

    
    return ptr;
}


/// m61_free(ptr, file, line)
///    Frees the memory allocation pointed to by `ptr`. If `ptr == nullptr`,
///    does nothing. Otherwise, `ptr` must point to a currently active
///    allocation returned by `m61_malloc`. The free was called at location
///    `file`:`line`.

void m61_free(void* ptr, const char* file, int line) {
    // avoid uninitialized variable warnings
    (void) ptr, (void) file, (void) line;
    if(ptr != nullptr){
    --nactive; //decrement number of active allocations by one
    active_size = active_size - mp[ptr].sz; // keep track of the active size
    mp.erase(ptr); //get rid of the ptr in our map, effectively deleting it. now when we iterate through the map, it's simply all of the active allocations

    }
    
    // Your code here. The handout code does nothing!
}


/// m61_calloc(count, sz, file, line)
///    Returns a pointer a fresh dynamic memory allocation big enough to
///    hold an array of `count` elements of `sz` bytes each. Returned
///    memory is initialized to zero. The allocation request was at
///    location `file`:`line`. Returns `nullptr` if out of memory; may
///    also return `nullptr` if `count == 0` or `size == 0`.

void* m61_calloc(size_t count, size_t sz, const char* file, int line) {
    // Your code here (not needed for first tests).
    if(count == 0){
        return m61_malloc(0);
    }
    if((default_buffer.size - default_buffer.pos) / count < sz){ // Since sz * count could overflow, we divide by count instead to ensure that our comparisons are accurate. 
        ++nfail; 
        fail_size = fail_size + count * sz; // The total memory allocated would be the size of any element multiplied by the number of elements in the array. 
        return nullptr;
    }
    void* ptr = m61_malloc(count * sz, file, line); //calloc is just malloc count times
    if (ptr) {
        memset(ptr, 0, count * sz);
    }
    return ptr;
}


/// m61_get_statistics()
///    Return the current memory statistics.

m61_statistics m61_get_statistics() {
    
    // The handout code sets all statistics to enormous numbers.
    m61_statistics stats;
    memset(&stats, 0, sizeof(m61_statistics)); // We initialize all to zero

    // Update all of the values of the statistics based on our updates throughout the code
    stats.ntotal = ntotal;
    stats.nactive = nactive;
    stats.total_size = total_size;
    stats.nfail = nfail;
    stats.fail_size = fail_size;
    stats.heap_max = heap_max;
    stats.heap_min = heap_min;
    stats.active_size = active_size;
    return stats;
}


/// m61_print_statistics()
///    Prints the current memory statistics.

void m61_print_statistics() {
    m61_statistics stats = m61_get_statistics();
    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// m61_print_leak_report()
///    Prints a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_print_leak_report() {
    // Your code here.
}
