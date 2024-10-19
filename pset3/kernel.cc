#include "kernel.hh"
#include "k-apic.hh"
#include "k-vmiter.hh"
#include "obj/k-firstprocess.h"
#include <atomic>

// kernel.cc
//
//    This is the kernel.


// INITIAL PHYSICAL MEMORY LAYOUT
//
//  +-------------- Base Memory --------------+
//  v                                         v
// +-----+--------------------+----------------+--------------------+---------/
// |     | Kernel      Kernel |       :    I/O | App 1        App 1 | App 2
// |     | Code + Data  Stack |  ...  : Memory | Code + Data  Stack | Code ...
// +-----+--------------------+----------------+--------------------+---------/
// 0  0x40000              0x80000 0xA0000 0x100000             0x140000
//                                             ^
//                                             | \___ PROC_SIZE ___/
//                                      PROC_START_ADDR

#define PROC_SIZE 0x40000       // initial state only

proc ptable[PID_MAX];           // array of process descriptors
                                // Note that `ptable[0]` is never used.
proc* current;                  // pointer to currently executing proc

#define HZ 100                  // timer interrupt frequency (interrupts/sec)
static std::atomic<unsigned long> ticks; // # timer interrupts so far


// Memory state - see `kernel.hh`
physpageinfo physpages[NPAGES];


[[noreturn]] void schedule();
[[noreturn]] void run(proc* p);
void exception(regstate* regs);
uintptr_t syscall(regstate* regs);
void memshow();


// kernel_start(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

static void process_setup(pid_t pid, const char* program_name);

void kernel_start(const char* command) {
    // initialize hardware
    init_hardware();
    log_printf("Starting WeensyOS\n");

    ticks = 1;
    init_timer(HZ);

    // clear screen
    console_clear();

    // (re-)initialize kernel page table
    for (uintptr_t addr = 0; addr < MEMSIZE_PHYSICAL; addr += PAGESIZE) {
        int perm = PTE_P | PTE_W | PTE_U;
        if (addr == 0) {
            // nullptr is inaccessible even to the kernel
            perm = 0;
        }
        else if ((addr < 0x100000) & addr != 0xB8000){
            perm = PTE_P | PTE_W;
        }
        // install identity mapping
        int r = vmiter(kernel_pagetable, addr).try_map(addr, perm);
        assert(r == 0); // mappings during kernel_start MUST NOT fail
                        // (Note that later mappings might fail!!)
    }

    // set up process descriptors
    for (pid_t i = 0; i < PID_MAX; i++) {
        ptable[i].pid = i;
        ptable[i].state = P_FREE;
    }
    if (!command) {
        command = WEENSYOS_FIRST_PROCESS;
    }
    if (!program_image(command).empty()) {
        process_setup(1, command);
    } else {
        process_setup(1, "allocator");
        process_setup(2, "allocator2");
        process_setup(3, "allocator3");
        process_setup(4, "allocator4");
    }

    // switch to first process using run()
    run(&ptable[1]);
}


// kalloc(sz)
//    Kernel physical memory allocator. Allocates at least `sz` contiguous bytes
//    and returns a pointer to the allocated memory, or `nullptr` on failure.
//    The returned pointer’s address is a valid physical address, but since the
//    WeensyOS kernel uses an identity mapping for virtual memory, it is also a
//    valid virtual address that the kernel can access or modify.
//
//    The allocator selects from physical pages that can be allocated for
//    process use (so not reserved pages or kernel data), and from physical
//    pages that are currently unused (`physpages[N].refcount == 0`).
//
//    On WeensyOS, `kalloc` is a page-based allocator: if `sz > PAGESIZE`
//    the allocation fails; if `sz < PAGESIZE` it allocates a whole page
//    anyway.
//
//    The returned memory is initially filled with 0xCC, which corresponds to
//    the `int3` instruction. Executing that instruction will cause a `PANIC:
//    Unhandled exception 3!` This may help you debug.

void* kalloc(size_t sz) {
    if (sz > PAGESIZE) {
        return nullptr;
    }

    int pageno = 0;
    int page_increment = 7;
    // In the handout code, `kalloc` returns the first free page.
    // Alternate search strategies can be faster and/or expose bugs elsewhere.
    // This initialization returns a random free page:
    //     int pageno = rand(0, NPAGES - 1);
    // This initialization remembers the most-recently-allocated page and
    // starts the search from there:
    //     static int pageno = 0;
    // In Step 3, you must change the allocation to use non-sequential pages.
    // The easiest way to do this is to set page_increment to 3, but you can
    // also set `pageno` randomly.

    for (int tries = 0; tries != NPAGES; ++tries) {
        uintptr_t pa = pageno * PAGESIZE;
        if (allocatable_physical_address(pa)
            && physpages[pageno].refcount == 0) {
            ++physpages[pageno].refcount;
            memset((void*) pa, 0xCC, PAGESIZE);
            return (void*) pa;
        }
        pageno = (pageno + page_increment) % NPAGES;
    }

    return nullptr;
}


// kfree(kptr)
//    Free `kptr`, which must have been previously returned by `kalloc`.
//    If `kptr == nullptr` does nothing.

void kfree(void* kptr) {
    if (kptr == nullptr){
        return; //no need to do anything
    }
    uintptr_t pa = (uintptr_t) kptr;
    if (!allocatable_physical_address(pa)) {
        return; //we need to free something
    }

    unsigned int pageno = pa / PAGESIZE; //calculate the page number

    if (physpages[pageno].refcount > 0) {
        --physpages[pageno].refcount;
    } else {
        return; // if recount is less than 1, invalid free
    }

}

void free_pagetable(x86_64_pagetable* pagetable) {

    if (pagetable == nullptr) { //no need to do anything
        return;
    }

    for (vmiter it(pagetable, 0); it.va() < MEMSIZE_VIRTUAL; it += PAGESIZE) {
        if (it.present() && it.user() && it.va() != CONSOLE_ADDR) {
        kfree((void*) it.pa()); // go through the pagetable and individually free each mapping
        }
    }
    for (ptiter it(pagetable); !it.done(); it.next()) {
    kfree(it.kptr()); //wahoo!!
    }
    kfree(pagetable);
}

// process_setup(pid, program_name)
//    Load application program `program_name` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.

void process_setup(pid_t pid, const char* program_name) {
    init_process(&ptable[pid], 0);

    // initialize process page table
    ptable[pid].pagetable = kalloc_pagetable();

    //identity mapping for the entries before proc_start_addr
    for (vmiter it(kernel_pagetable, 0); it.va() < PROC_START_ADDR; it += PAGESIZE){
        int r = vmiter(ptable[pid].pagetable, it.va()).try_map(it.pa(), it.perm());
    }

    
    // obtain reference to program image
        // (The program image models the process executable.)
        program_image pgm(program_name);
    // allocate and map process memory as specified in program image
    for (auto seg = pgm.begin(); seg != pgm.end(); ++seg) {
        for (uintptr_t a = round_down(seg.va(), PAGESIZE); 
             a < seg.va() + seg.size(); 
             a += PAGESIZE) {
            // `a` is the process virtual address for the next code/data page
            // (The handout code requires that the corresponding physical
            // address is currently free.)
            int perm = PTE_P | PTE_W | PTE_U;
            if (!seg.writable()) {
                perm = PTE_P | PTE_U;
            }
            auto pa = (uintptr_t) kalloc(PAGESIZE);
            int r = vmiter(ptable[pid].pagetable, a).try_map(pa, perm);
        }
    }

    // mark entry point
    ptable[pid].regs.reg_rip = pgm.entry();

    // allocate and map stack segment
    // Compute process virtual address for stack page
    uintptr_t stack_addr = MEMSIZE_VIRTUAL - PAGESIZE;
    // The handout code requires that the corresponding physical address
    // is currently free.
    
    auto pa = (uintptr_t) kalloc(PAGESIZE);
    int r = vmiter(ptable[pid].pagetable, stack_addr).try_map(pa, PTE_P | PTE_W | PTE_U);

    // copy instructions and data from program image into process memory
    for (auto seg = pgm.begin(); seg != pgm.end(); ++seg) {
        size_t data_index = 0; //pointer to the current seg data
        for (uintptr_t addr = seg.va(); addr < seg.va() + seg.size(); addr += PAGESIZE) {
            uintptr_t physical_addr = vmiter(ptable[pid].pagetable,addr).pa();
            memset((void*) physical_addr,0,PAGESIZE);
            
            if (data_index < seg.data_size()) { //of our pointer goes out of bounds, figure out how much data to copy, and change the offset
                size_t copy_size = PAGESIZE;
                memcpy((void*) physical_addr, seg.data() + data_index, copy_size); //use memcpy to copy the data from the segment into the physical memory
                data_index += copy_size; //iterate through the data_index
            }
        }
    }

    // assert(physpages[stack_addr / PAGESIZE].refcount == 0);
    // ++physpages[stack_addr / PAGESIZE].refcount;
    ptable[pid].regs.reg_rsp = stack_addr + PAGESIZE;
    // mark process as runnable
    ptable[pid].state = P_RUNNABLE;
}

void syscall_exit(int pid) {
    x86_64_pagetable* pagetable = ptable[pid].pagetable;
    free_pagetable(pagetable);

    //reset the pagetable slot
    ptable[pid].pagetable = nullptr;
    ptable[pid].regs = regstate();
    ptable[pid].state = P_FREE;
    
    
    
    }



// exception(regs)
//    Exception handler (for interrupts, traps, and faults).
//
//    The register values from exception time are stored in `regs`.
//    The processor responds to an exception by saving application state on
//    the kernel's stack, then jumping to kernel assembly code (in
//    k-exception.S). That code saves more registers on the kernel's stack,
//    then calls exception().
//
//    Note that hardware interrupts are disabled when the kernel is running.

void exception(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: exception %d at rip %p\n",
                current->pid, regs->reg_intno, regs->reg_rip); */

    // Show the current cursor location and memory state
    // (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    if (regs->reg_intno != INT_PF || (regs->reg_errcode & PTE_U)) {
        memshow();
    }

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (regs->reg_intno) {

    case INT_IRQ + IRQ_TIMER:
        ++ticks;
        lapicstate::get().ack();
        schedule();
        break;                  /* will not be reached */

    case INT_PF: {
        // Analyze faulting address and access type.
        uintptr_t addr = rdcr2();
        const char* operation = regs->reg_errcode & PTE_W
                ? "write" : "read";
        const char* problem = regs->reg_errcode & PTE_P
                ? "protection problem" : "missing page";

        if (!(regs->reg_errcode & PTE_U)) {
            proc_panic(current, "Kernel page fault on %p (%s %s, rip=%p)!\n",
                       addr, operation, problem, regs->reg_rip);
        }
        error_printf(CPOS(24, 0), COLOR_ERROR,
                     "PAGE FAULT on %p (pid %d, %s %s, rip=%p)!\n",
                     addr, current->pid, operation, problem, regs->reg_rip);
        log_print_backtrace(current);
        current->state = P_FAULTED;
        break;
    }

    default:
        proc_panic(current, "Unhandled exception %d (rip=%p)!\n",
                   regs->reg_intno, regs->reg_rip);

    }

    // Return to the current process (or run something else).
    if (current->state == P_RUNNABLE) {
        run(current);
    } else {
        schedule();
    }
}


int syscall_page_alloc(uintptr_t addr);
int syscall_fork(int parent, regstate parent_regs);
void syscall_exit(int pid);

// syscall(regs)
//    Handle a system call initiated by a `syscall` instruction.
//    The process’s register values at system call time are accessible in
//    `regs`.
//
//    If this function returns with value `V`, then the user process will
//    resume with `V` stored in `%rax` (so the system call effectively
//    returns `V`). Alternately, the kernel can exit this function by
//    calling `schedule()`, perhaps after storing the eventual system call
//    return value in `current->regs.reg_rax`.
//
//    It is only valid to return from this function if
//    `current->state == P_RUNNABLE`.
//
//    Note that hardware interrupts are disabled when the kernel is running.

uintptr_t syscall(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: syscall %d at rip %p\n",
                  current->pid, regs->reg_rax, regs->reg_rip); */

    // Show the current cursor location and memory state.
    console_show_cursor(cursorpos);
    memshow();

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (regs->reg_rax) {

    case SYSCALL_PANIC:
        user_panic(current);
        break; // will not be reached

    case SYSCALL_GETPID:
        return current->pid;

    case SYSCALL_YIELD:
        current->regs.reg_rax = 0;
        schedule();             // does not return

    case SYSCALL_PAGE_ALLOC:
        return syscall_page_alloc(current->regs.reg_rdi);
    
    case SYSCALL_FORK:
        return syscall_fork(current->pid,current->regs);
    
    case SYSCALL_EXIT:
        syscall_exit(current->pid);
        schedule();

    default:
        proc_panic(current, "Unhandled system call %ld (pid=%d, rip=%p)!\n",
                   regs->reg_rax, current->pid, regs->reg_rip);

    }

    panic("Should not get here!\n");
}



// syscall_page_alloc(addr)
//    Handles the SYSCALL_PAGE_ALLOC system call. This function
//    should implement the specification for `sys_page_alloc`
//    in `u-lib.hh` (but in the handout code, it does not).

int syscall_page_alloc(uintptr_t addr) {
    if (addr ==0 || addr % PAGESIZE  != 0|| addr < PROC_START_ADDR || addr >= MEMSIZE_VIRTUAL) {
        return -1;
    }

    uintptr_t a = (uintptr_t) kalloc(PAGESIZE);
    if (a == 0) {
        return -1;
    }
    // assert(physpages[addr / PAGESIZE].refcount == 0);
    // ++physpages[addr / PAGESIZE].refcount;
    int r = vmiter(current -> pagetable, addr).try_map(a, PTE_P | PTE_W | PTE_U);
    if (r != 0) {
        return -1;
    }
    uintptr_t physical_addr = vmiter(current -> pagetable, addr).pa();
    memset((void*) physical_addr, 0, PAGESIZE);
    return 0;
}


int syscall_fork(int parent, regstate parent_regs) {
    int child = -1; // init at -1, and then jump to 1 so we avoid 0
    for (int pid = 1; pid < PID_MAX; ++pid) {
        if (ptable[pid].state == P_FREE && pid != parent) {
            child = pid;
            break;
        }
    }
    if (child == -1) {
        return -1;  // if there's no free process, return -1 instead of killing the calling sequence
    }

    x86_64_pagetable* parentpagetable = ptable[parent].pagetable;
    x86_64_pagetable* childpagetable = kalloc_pagetable(); //kalloc a pagetable for the child

    if(childpagetable == nullptr){
        return -1; //memory allocation failure
    }

    //identity mapping for addresses before proc_start_addr
    //same as our kernel identity mapping
    for (uintptr_t addr = 0; addr < PROC_START_ADDR; addr += PAGESIZE) {
        int r = vmiter(childpagetable, addr).try_map(vmiter(parentpagetable,addr).pa(), vmiter(parentpagetable,addr).perm());
        if (r != 0) {
        return -1; 
        }  
    }
    //for everything above PROC_START_ADDR
    for (vmiter iterparent(parentpagetable, PROC_START_ADDR); iterparent.va() < MEMSIZE_VIRTUAL; iterparent += PAGESIZE){
        //store information about the permission and physical addresses of the parent
        //we want to specifically check for addresses that have all of the permissions
        if(iterparent.present()){
            if(iterparent.writable()){
            void* child_pa = kalloc(PAGESIZE);
            if(child_pa == nullptr){
                //not enough space
                free_pagetable(childpagetable); //free the pagetable so we can restart
                return -1;
            }

            int r = vmiter(childpagetable, iterparent.va()).try_map((uintptr_t) child_pa, iterparent.perm());

            if(r != 0){
                kfree(child_pa);
                free_pagetable(childpagetable);
                return -1;
            }
            memcpy(child_pa, (void*) iterparent.pa(), PAGESIZE);
        }
        //if they don't have all of the permissions, then we want to share this page with the parent
        else{
            unsigned int pageno = iterparent.pa() / PAGESIZE;
            ++physpages[pageno].refcount;
            int r = vmiter(childpagetable, iterparent.va()).try_map(iterparent.pa(), iterparent.perm());
            if (r != 0) {
            free_pagetable(childpagetable);
            return -1;
            }
        }
    }
        } 
    ptable[child].pagetable = childpagetable;
    ptable[child].regs = parent_regs;
    ptable[child].regs.reg_rax = 0;
    ptable[child].state = P_RUNNABLE;

    return child;
}




// schedule
//    Pick the next process to run and then run it.
//    If there are no runnable processes, spins forever.

void schedule() {
    pid_t pid = current->pid;
    for (unsigned spins = 1; true; ++spins) {
        pid = (pid + 1) % PID_MAX;
        if (ptable[pid].state == P_RUNNABLE) {
            run(&ptable[pid]);
        }

        // If Control-C was typed, exit the virtual machine.
        check_keyboard();

        // If spinning forever, show the memviewer.
        if (spins % (1 << 12) == 0) {
            memshow();
        }
    }
}




// run(p)
//    Run process `p`. This involves setting `current = p` and calling
//    `exception_return` to restore its page table and registers.

void run(proc* p) {
    assert(p->state == P_RUNNABLE);
    current = p;

    // Check the process's current registers.
    check_process_registers(p);

    // Check the process's current pagetable.
    check_pagetable(p->pagetable);

    // This function is defined in k-exception.S. It restores the process's
    // registers then jumps back to user mode.
    exception_return(p);

    // should never get here
    while (true) {
    }
}


// memshow()
//    Draw a picture of memory (physical and virtual) on the CGA console.
//    Switches to a new process's virtual memory map every 0.25 sec.
//    Uses `console_memviewer()`, a function defined in `k-memviewer.cc`.

void memshow() {
    static unsigned last_ticks = 0;
    static int showing = 0;

    // switch to a new process every 0.25 sec
    if (last_ticks == 0 || ticks - last_ticks >= HZ / 2) {
        last_ticks = ticks;
        showing = (showing + 1) % PID_MAX;
    }

    proc* p = nullptr;
    for (int search = 0; !p && search < PID_MAX; ++search) {
        if (ptable[showing].state != P_FREE
            && ptable[showing].pagetable) {
            p = &ptable[showing];
        } else {
            showing = (showing + 1) % PID_MAX;
        }
    }

    console_memviewer(p);
    if (!p) {
        console_printf(CPOS(10, 26), 0x0F00, "   VIRTUAL ADDRESS SPACE\n"
            "                          [All processes have exited]\n"
            "\n\n\n\n\n\n\n\n\n\n\n");
    }
}
