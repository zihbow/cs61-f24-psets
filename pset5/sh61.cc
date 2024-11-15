// sh61.cc
#include "sh61.hh"
#include <cstring>
#include <cerrno>
#include <vector>
#include <array>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>  // For chdir

// For the love of God
#undef exit
#define exit __DO_NOT_CALL_EXIT__READ_PROBLEM_SET_DESCRIPTION__

// Global variable to track the quiet mode
bool quiet = false;

// struct command
//    Data structure describing a command. Add your own stuff.

enum class Operator { // determine the operator associated with the current command
    NONE,
    SEMICOLON, // ;
    AND,       // &&
    OR,        // ||
    PIPE,      // |
    AMPERSAND  // &
};

struct command {
    std::vector<std::string> args;
    pid_t pid = -1;
    Operator op = Operator::NONE;

    // Redirection filenames
    std::string input_file;       // '<' redirection
    std::string output_file;      // '>' redirection
    std::string error_file;       // '2>' redirection

    command();
    ~command();

    void run();
    bool is_builtin();            // check for built-in commands
    int run_builtin();            // execute built-in commands
};

command::command() {
}

command::~command() {
}

// COMMAND EXECUTION



bool command::is_builtin() { //for convenience :)
    // Check if the command is "cd"
    return !args.empty() && args[0] == "cd";
}


int command::run_builtin() { //executes a command without forking into child process
    int status = 0;

    //input redirection
    int saved_stdin = -1;
    if (!input_file.empty()) {
        saved_stdin = dup(STDIN_FILENO);
        int fd = open(input_file.c_str(), O_RDONLY);
        if (fd == -1) {
            fprintf(stderr, "%s: %s\n", input_file.c_str(), strerror(errno));
            return 1;
        }
        if (dup2(fd, STDIN_FILENO) == -1) {
            perror("dup2");
            close(fd);
            return 1;
        }
        close(fd);
    }

    //output redirection
    int saved_stdout = -1;
    if (!output_file.empty()) {
        saved_stdout = dup(STDOUT_FILENO);
        int fd = open(output_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd == -1) {
            fprintf(stderr, "%s: %s\n", output_file.c_str(), strerror(errno));
            // restore stdin if it was redirected
            if (saved_stdin != -1) {
                dup2(saved_stdin, STDIN_FILENO);
                close(saved_stdin);
            }
            return 1;
        }
        if (dup2(fd, STDOUT_FILENO) == -1) {
            perror("dup2");
            close(fd);
            // Restore stdin if it was redirected
            if (saved_stdin != -1) {
                dup2(saved_stdin, STDIN_FILENO);
                close(saved_stdin);
            }
            return 1;
        }
        close(fd);
    }

    //error redirection
    int saved_stderr = -1;
    if (!error_file.empty()) {
        saved_stderr = dup(STDERR_FILENO);
        int fd = open(error_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd == -1) {
            fprintf(stderr, "%s: %s\n", error_file.c_str(), strerror(errno));
            // Restore stdin and stdout if they were redirected
            if (saved_stdin != -1) {
                dup2(saved_stdin, STDIN_FILENO);
                close(saved_stdin);
            }
            if (saved_stdout != -1) {
                dup2(saved_stdout, STDOUT_FILENO);
                close(saved_stdout);
            }
            return 1;
        }
        if (dup2(fd, STDERR_FILENO) == -1) {
            perror("dup2");
            close(fd);
            // Restore stdin and stdout if they were redirected
            if (saved_stdin != -1) {
                dup2(saved_stdin, STDIN_FILENO);
                close(saved_stdin);
            }
            if (saved_stdout != -1) {
                dup2(saved_stdout, STDOUT_FILENO);
                close(saved_stdout);
            }
            return 1;
        }
        close(fd);
    }

    // execute the built-in command
    if (args[0] == "cd") {
        const char* dir = nullptr;
        if (args.size() > 1) {
            dir = args[1].c_str();
        } else {
            dir = getenv("HOME");
            if (!dir) {
                dir = ".";
            }
        }
        if (chdir(dir) != 0) {
            fprintf(stderr, "cd: %s: %s\n", dir, strerror(errno));
            status = 1; // we failed
        }
    }

    //restore the file descriptors
    if (saved_stdin != -1) {
        dup2(saved_stdin, STDIN_FILENO);
        close(saved_stdin);
    }
    if (saved_stdout != -1) {
        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }
    if (saved_stderr != -1) {
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
    }

    return status; // return the exit status of the built-in command
}

// command::run()
//    Creates a single child process running the command in `this`, and
//    sets `this->pid` to the pid of the child process.
//
//    If a child process cannot be created, this function should call
//    `_exit(EXIT_FAILURE)` (that is, `_exit(1)`) to exit the containing
//    shell or subshell. If this function returns to its caller,
//    `this->pid > 0` must always hold.
//
//    Note that this function must return to its caller *only* in the parent
//    process. The code that runs in the child process must `execvp` and/or
//    `_exit`.
//
//    PHASE 1: Fork a child process and run the command using `execvp`.
//       This will require creating a vector of `char*` arguments using
//       `this->args[N].c_str()`. Note that the last element of the vector
//       must be a `nullptr`.
//    PHASE 4: Set up a pipeline if appropriate. This may require creating a
//       new pipe (`pipe` system call), and/or replacing the child process's
//       standard input/output with parts of the pipe (`dup2` and `close`).
//       Draw pictures!
//    PHASE 7: Handle redirections.

void command::run() {
    assert(this->pid == -1);

    // Check for built-in commands
    if (this->is_builtin()) {
        this->run_builtin();
        return;
    }

    assert(this->args.size() > 0);
    this->pid = fork();
    if (this->pid == -1) {
        _exit(EXIT_FAILURE);
    } else if (this->pid == 0) { // forked successfully, child process initiate

        // input redirection
        if (!input_file.empty()) {
            int fd = open(input_file.c_str(), O_RDONLY);
            if (fd == -1) {
                //print stderr
                fprintf(stderr, "%s: %s\n", input_file.c_str(), strerror(errno));
                _exit(EXIT_FAILURE);
            }
            if (dup2(fd, STDIN_FILENO) == -1) {
                close(fd);
                _exit(EXIT_FAILURE);
            }
            close(fd);
        }

        //output redirection
        if (!output_file.empty()) {
            int fd = open(output_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (fd == -1) {
                //print stderr
                fprintf(stderr, "%s: %s\n", output_file.c_str(), strerror(errno));
                _exit(EXIT_FAILURE);
            }
            if (dup2(fd, STDOUT_FILENO) == -1){
                close(fd);
                _exit(EXIT_FAILURE);
            }
            close(fd);
        }

        //error redirection
        if (!error_file.empty()) {
            int fd = open(error_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (fd == -1) {
                //print stderr
                fprintf(stderr, "%s: %s\n", error_file.c_str(), strerror(errno));
                _exit(EXIT_FAILURE);
            }
            if (dup2(fd, STDERR_FILENO) == -1) {
                perror("dup2");
                close(fd);
                _exit(EXIT_FAILURE);
            }
            close(fd);
        }

        std::vector<char*> argv;
        for (const auto& arg : this->args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr); // ensure that the last element is nullptr

        execvp(argv[0], argv.data());

        // if execvp returns, it failed
        perror("execvp");
        _exit(EXIT_FAILURE);
    }
}


int run_pipeline(std::vector<command*> pipeline_cmds, bool background) { //return the status so we can go down the line
    size_t n = pipeline_cmds.size();
    std::vector<pid_t> pids(n);
    std::vector<std::array<int, 2>> pipes(n - 1); // each pipe has two fds (read/write)

    //create pipes
    for (size_t i = 0; i < n - 1; ++i) {
        if (pipe(pipes[i].data()) == -1) {
            //close any previously opened pipes
            for (size_t j = 0; j < i; ++j) {
                close(pipes[j][0]);
                close(pipes[j][1]);
            }
            return -1; //status
        }
    }

    for (size_t i = 0; i < n; ++i) {
        pid_t pid = fork();
        if (pid == -1) { //if child fails, close all pipes
            for (size_t j = 0; j < n - 1; ++j) {
                close(pipes[j][0]);
                close(pipes[j][1]);
            }
            return -1; //status
        } else if (pid == 0) {
            // Child process

            // if not the first command, redirect stdin to the previous pipe's read end
            if (i > 0) {
                if (dup2(pipes[i - 1][0], STDIN_FILENO) == -1) {
                    _exit(EXIT_FAILURE);
                }
            }

            // if not the last command, redirect stdout to the current pipe's write end
            if (i < n - 1) {
                if (dup2(pipes[i][1], STDOUT_FILENO) == -1) {
                    _exit(EXIT_FAILURE);
                }
            }

            // close all pipe fds in the child
            for (size_t j = 0; j < n - 1; ++j) {
                close(pipes[j][0]);
                close(pipes[j][1]);
            }

            // input redirection
            if (!pipeline_cmds[i]->input_file.empty()) {
                int fd = open(pipeline_cmds[i]->input_file.c_str(), O_RDONLY);
                if (fd == -1) {
                    // print error msg
                    fprintf(stderr, "%s: %s\n", pipeline_cmds[i]->input_file.c_str(), strerror(errno));
                    _exit(EXIT_FAILURE);
                }
                if (dup2(fd, STDIN_FILENO) == -1) {
                    close(fd);
                    _exit(EXIT_FAILURE);
                }
                close(fd);
            }

            // output redirection
            if (!pipeline_cmds[i]->output_file.empty()) {
                int fd = open(pipeline_cmds[i]->output_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
                if (fd == -1) {
                    //same as input redir
                    fprintf(stderr, "%s: %s\n", pipeline_cmds[i]->output_file.c_str(), strerror(errno));
                    _exit(EXIT_FAILURE);
                }
                if (dup2(fd, STDOUT_FILENO) == -1) {
                    close(fd);
                   _exit(EXIT_FAILURE);
                }
                close(fd);
            }

            // error redirection
            if (!pipeline_cmds[i]->error_file.empty()) {
                int fd = open(pipeline_cmds[i]->error_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
                if (fd == -1) {
                    //ditto
                    fprintf(stderr, "%s: %s\n", pipeline_cmds[i]->error_file.c_str(), strerror(errno));
                    _exit(EXIT_FAILURE);
                }
                if (dup2(fd, STDERR_FILENO) == -1) {
                    close(fd);
                    _exit(EXIT_FAILURE);
                }
                close(fd);
            }

            // execute the command
            std::vector<char*> argv;
            for (const auto& arg : pipeline_cmds[i]->args) {
                argv.push_back(const_cast<char*>(arg.c_str()));
            }
            argv.push_back(nullptr);

            execvp(argv[0], argv.data());

            //if execvp doesn't return
            _exit(EXIT_FAILURE);
        } else {
            //parent process
            pids[i] = pid;
        }
    }

    // close all pipe fds in the parent
    for (size_t i = 0; i < n - 1; ++i) {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }

    // wait for all child processes
    if (!background) {
        int status = 0;
        for (size_t i = 0; i < n; ++i) {
            int cmd_status;
            waitpid(pids[i], &cmd_status, 0);

            // we want to retain the exit status of the last command
            if (i == n - 1) {
                if (WIFEXITED(cmd_status)) {
                    status = WEXITSTATUS(cmd_status);
                } else if (WIFSIGNALED(cmd_status)) {
                    status = 128 + WTERMSIG(cmd_status);
                } else {
                    status = 1; // Default non-zero status
                }
            }
        }
        return status;
    } else {
        // for background pipelines, don't wait
        if (!quiet) {
            _exit(EXIT_FAILURE);
        }
        return 0;
    }
}


int run_command_list(const std::vector<command*>& commands) { //helper function, runs lists of commands
    int last_status = 0;
    Operator last_op = Operator::SEMICOLON;

    size_t i = 0;
    while (i < commands.size()) {
        command* cmd = commands[i];
        bool should_run = false;

        // Determine if we should run the command based on the last operator and status
        if (last_op == Operator::SEMICOLON) {
            should_run = true;
        } else if (last_op == Operator::AND) {
            if (WIFEXITED(last_status) && WEXITSTATUS(last_status) == 0) {
                should_run = true;
            }
        } else if (last_op == Operator::OR) {
            if (!(WIFEXITED(last_status) && WEXITSTATUS(last_status) == 0)) {
                should_run = true;
            }
        }

        if (should_run) {
            // handle built-in commands
            if (cmd->is_builtin()) {
                last_status = cmd->run_builtin();
                last_status <<= 8; //no child process is being created, so we have to match this format to the expected format for WIFEXITED and WEXITSTATUS
                last_op = cmd->op;
                ++i;
                continue;
            }

            //check if it's a pipeline
            if ((cmd->op == Operator::PIPE) || (i + 1 < commands.size() && commands[i + 1]->op == Operator::PIPE)) {

                std::vector<command*> pipeline; //figure out what's in the pipeline, and add it to our list of commands
                pipeline.push_back(cmd);
                while (i + 1 < commands.size() && commands[i]->op == Operator::PIPE) {
                    ++i;
                    cmd = commands[i];
                    pipeline.push_back(cmd);
                }

                last_status = run_pipeline(pipeline, false);
                last_status <<= 8; 
                last_op = cmd->op;
                ++i;
            } else { //it's a single command, and we can just run it as we always do
                cmd->run();
                waitpid(cmd->pid, &last_status, 0);
                last_op = cmd->op;
                ++i;
            }
        } else {
            //skip the command
            last_op = cmd->op;
            ++i;
        }
    }

    return last_status;
}

// run_list(c)
//    Run the command *list* contained in `section`.
//
//    PHASE 1: Use `waitpid` to wait for the command started by `c->run()`
//        to finish.
//
//    The remaining phases may require that you introduce helper functions
//    (e.g., to process a pipeline), write code in `command::run`, and/or
//    change `struct command`.
//
//    It is possible, and not too ugly, to handle lists, conditionals,
//    *and* pipelines entirely within `run_list`, but in general it is clearer
//    to introduce `run_conditional` and `run_pipeline` functions that
//    are called by `run_list`. It’s up to you.
//
//    PHASE 2: Introduce a loop to run a list of commands, waiting for each
//       to finish before going on to the next.
//    PHASE 3: Change the loop to handle conditional chains.
//    PHASE 4: Change the loop to handle pipelines. Start all processes in
//       the pipeline in parallel. The status of a pipeline is the status of
//       its LAST command.
//    PHASE 5: Change the loop to handle background conditional chains.
//       This may require adding another call to `fork()`!

void run_list(shell_parser sec) {
    struct command_list { //create a list of commands with a background parameter
        std::vector<command*> commands;
        bool background;
    };

    std::vector<command_list> command_lists;

    auto tok = sec.first_token(); //start with the first token
    command* c = new command;
    command_list clist; //initialize list of commands
    clist.background = false;

    while (tok) { //go through each token and identify what makes up the token and the operators involved
        if (tok.type() == TYPE_REDIRECT_OP) {
            std::string redirect_op = tok.str();
            tok.next();
            if (!tok || tok.type() != TYPE_NORMAL) {
                break; //redirection without a filename
            }
            std::string filename = tok.str();
            if (redirect_op == "<") {
                c->input_file = filename;
            } else if (redirect_op == ">") {
                c->output_file = filename;
            } else if (redirect_op == "2>") {
                c->error_file = filename;
            }
        } else if (tok.type() == TYPE_SEQUENCE) {
            //handle a specific operator
            c->op = Operator::SEMICOLON; //identify operator
            clist.commands.push_back(c); 
            command_lists.push_back(clist);
            clist = command_list(); 
            clist.background = false; //background
            c = new command;
        } else if (tok.type() == TYPE_BACKGROUND) {
            c->op = Operator::AMPERSAND;
            clist.commands.push_back(c); 
            clist.background = true;
            command_lists.push_back(clist); //put clist on to the command_lists as background, then continue
            clist = command_list();
            clist.background = false;
            c = new command;
        } else if (tok.type() == TYPE_AND) {
            c->op = Operator::AND;
            clist.commands.push_back(c);
            c = new command;
        } else if (tok.type() == TYPE_OR) {
            c->op = Operator::OR;
            clist.commands.push_back(c);
            c = new command;
        } else if (tok.type() == TYPE_PIPE) {
            c->op = Operator::PIPE;
            clist.commands.push_back(c);
            c = new command;
        } else {
            //if it's just a simple command
            c->args.push_back(tok.str());
        }
        tok.next();
    }

    // deal with the last command
    if (!c->args.empty() || !c->input_file.empty() || !c->output_file.empty() || !c->error_file.empty()) {
        clist.commands.push_back(c);
    } else {
        delete c;
    }
    if (!clist.commands.empty()) {
        command_lists.push_back(clist);
    }

    // now process each list of commands
    int last_status = 0;

    for (auto& clist : command_lists) {
        if (clist.background) { // if it's supposed to be in the background
            pid_t bg_pid = fork();
            if (bg_pid == -1) { // fork failure
                perror("fork");
            } else if (bg_pid == 0) {
                // Run the command list
                int status = run_command_list(clist.commands);
                _exit(status); // exit with the status
            } else {
                //parent process
                if (!quiet) {
                    fprintf(stderr, "[%d] %d\n", bg_pid, bg_pid);
                }
                // Do not wait for bg_pid
            }
        } else {
            // foreground command list
            last_status = run_command_list(clist.commands);
        }
    }

    // clean up
    for (auto& clist : command_lists) {
        for (auto& cmd : clist.commands) {
            delete cmd;
        }
    }
}

int main(int argc, char* argv[]) {
    FILE* command_file = stdin;

    // Check for `-q` option: be quiet (print no prompts)
    if (argc > 1 && strcmp(argv[1], "-q") == 0) {
        quiet = true;
        --argc, ++argv;
    }

    // Check for filename option: read commands from file
    if (argc > 1) {
        command_file = fopen(argv[1], "rb");
        if (!command_file) {
            perror(argv[1]);
            return 1;
        }
    }

    // - Put the shell into the foreground
    // - Ignore the SIGTTOU signal, which is sent when the shell is put back
    //   into the foreground
    claim_foreground(0);
    set_signal_handler(SIGTTOU, SIG_IGN);

    char buf[BUFSIZ];
    int bufpos = 0;
    bool needprompt = true;

    while (!feof(command_file)) {
        // Print the prompt at the beginning of the line
        if (needprompt && !quiet) {
            printf("sh61[%d]$ ", getpid());
            fflush(stdout);
            needprompt = false;
        }

        // Read a string, checking for error or EOF
        if (fgets(&buf[bufpos], BUFSIZ - bufpos, command_file) == nullptr) {
            if (ferror(command_file) && errno == EINTR) {
                // Ignore EINTR errors
                clearerr(command_file);
                buf[bufpos] = 0;
            } else {
                if (ferror(command_file)) {
                    perror("sh61");
                }
                break;
            }
        }

        // If a complete command line has been provided, run it
        bufpos = strlen(buf);
        if (bufpos == BUFSIZ - 1 || (bufpos > 0 && buf[bufpos - 1] == '\n')) {
            run_list(shell_parser{buf});
            bufpos = 0;
            needprompt = true;

            // zombie processes
            pid_t pid;
            int status;
            while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
                if (!quiet) {
                    if (WIFEXITED(status)) {
                        fprintf(stderr, "[%d] exited with status %d\n", pid, WEXITSTATUS(status));
                    } else if (WIFSIGNALED(status)) {
                        fprintf(stderr, "[%d] terminated by signal %d\n", pid, WTERMSIG(status));
                    }
                }
            }
        }
    }

    return 0;
}
