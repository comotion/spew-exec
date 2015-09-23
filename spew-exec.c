/* process handling for spew
 spawn a process
   EXEC /some command
	  <- stdout
		<- stderr
 WRITE blah -> stdout

 signal SIGKILL -> to child
  <- DIED

*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define BUF_SIZE 1024
#define MAX_EVENTS 10
#ifndef TRACE
#define TRACE 0
#endif


struct sig { int num; char *name; } sigmap[] = {
	{SIGHUP,  "SIGHUP"},
	{SIGINT,  "SIGINT"},
	{SIGQUIT, "SIGQUIT"},
	{SIGILL,  "SIGILL"},
	{SIGTRAP, "SIGTRAP"},
	{SIGABRT, "SIGABRT"},
	{SIGIOT,  "SIGIOT"},
	{SIGBUS,  "SIGBUS"},
	{SIGFPE,  "SIGFBE"},
	{SIGKILL, "SIGKILL"},
	{SIGKILL, "KILL"},
	{SIGUSR1, "SIGURS1"},
	{SIGUSR1, "URS1"},
	{SIGSEGV, "SIGSEGV"},
	{SIGUSR2, "SIGUSR2"},
	{SIGUSR2, "USR2"},
	{SIGPIPE, "SIGPIPE"},
	{SIGALRM, "SIGALRM"},
	{SIGTERM, "SIGTERM"},
	{SIGTERM, "TERM"},
	{SIGSTKFLT, "SIGSTKFLT"},
	{SIGCHLD, "SIGCHLD"},
	{SIGCONT, "SIGCONT"},
	{SIGCONT, "CONT"},
	{SIGSTOP, "SIGSTOP"},
	{SIGSTOP, "STOP"},
	{SIGTSTP, "SIGTSTP"},
	{SIGTTIN, "SIGTTIN"},
	{SIGTTOU, "SIGTTOU"},
	{SIGURG,  "SIGURG"},
	{SIGXCPU, "SIGXCPU"},
	{SIGXFSZ, "SIGXFSZ"},
	{SIGVTALRM, "SIGVTALRM"},
	{SIGPROF, "SIGPROF"},
	{SIGWINCH, "SIGWINCH"},
	{SIGPOLL, "SIGPOLL"},
	{SIGIO, "SIGIO"},
	{SIGPWR, "SIGPWR"},
	{SIGSYS, "SIGSYS"},
	{SIGUNUSED, "SIGUNUSED"},

	{0, NULL},
};

// global pid of the executed child
pid_t child;
int chin, chout;
int epfd;
struct epoll_event  events[MAX_EVENTS];

int tok_args(char *args, char **argv)
{
	if (TRACE) printf("tok_args! %s\n", args);
	int i = 0;
	char *p;
	while( (p = strchr(args, ' ')) != NULL){
		if (TRACE) printf("arg %d: %s\n", i, argv[i]);
		argv[i++] = p + 1;
	  *p = '\0';
	}
	if(i == 0) { // only one argument
		argv[i++] = args;
	}
	argv[i] = NULL;
	return i;
}

int cmd_exec(char *commandstring, char * const envp[]) {
	char *path = NULL;
	char *p, *args = NULL;
	struct stat statbuf;
	char *parsedargs[1000];

	path = commandstring;
	p = strchr(path, '\n');
	if(p)
		*p = '\0';
	else {
		fprintf(stderr, "EXEC param too long, needs to be max %d bytes.\n", BUF_SIZE);
		exit(1);
	}

	p = strchr(path, ' ');
	// find arguments, if any
	if(p){
		*p = '\0';
		args = p + 1;
	}
	if((p = strchr(path, '\n')) != NULL){
			p = '\0';
	}
	if(0 != stat(path, &statbuf) || !S_ISREG(statbuf.st_mode) || !( S_IXUSR & statbuf.st_mode )){
			printf("Couldn't execute %s: %s\n", path, strerror(errno));
			return -1;
	}
	parsedargs[0] = path;
	parsedargs[1] = NULL;
	if(args != NULL) 
		tok_args(args, parsedargs +1);

	// we need fd's to child to send stdin and capture stdout?
	int infd[2];
	int outfd[2];
	if(pipe(infd) == -1) {
		perror("pipe infd");
		exit(2);
	}
	if(pipe(outfd) == -1) {
		perror("pipe outfd");
		exit(2);
	}

	child = fork();
	if(child == -1) {
			printf("Couldn't fork %s: %s\n", path, strerror(errno));
			exit(3);
	}

	if(child == 0) { // child
		if(dup2(infd[0], 0) != STDIN_FILENO) {; // child stdin = read end of inpipe
			perror("stdin if");
		}
    if(dup2(outfd[1], 1)!= STDOUT_FILENO) {;// stdout = write end of outpipe
			perror("stdout if");
 	  }
		//dup2(outfd[1], 2);// stderr = write end of outpipe
		//close(infd[1]);  // child only reads from infd
		//close(outfd[0]); // child only writes to outfd

		int rc = execve(path, parsedargs, envp);
		perror("execution failed");
	}else{ // parent
		char buf[1024]; 
		// parent writes to   infd
		// parent reads  from outfd
		chin = infd[1];
		chout = outfd[0];
		//close(infd[0]); 
		//close(outfd[1]); 
		if (TRACE) printf("HANDLE: %d/%d\n", chin, chout);

		struct epoll_event ev;
		ev.data.fd = chout;
		ev.events = EPOLLIN;
		if(epoll_ctl(epfd, EPOLL_CTL_ADD, chout, &ev) == -1) {
			perror("epoll_ctl");
		}
	}
}

int cmd_write(char *buffer){
	write(chin, buffer, strlen(buffer));
}

int cmd_signal(char *buffer){
	for(int i = 0; sigmap[i].name; i++){
		if(0 == strncmp(sigmap[i].name, buffer, strlen(sigmap[i].name))){
			kill(child, sigmap[i].num);
			return sigmap[i].num;
		}
	}
	fprintf(stderr, "SIGNAL does not exist in signum.h\n");
	return -1;
}

void handlesig(int sig) {
	if(sig == SIGPIPE){
		printf("DEAD\n");
	}else if(sig == SIGCHLD) {
		printf("DYING\n");
	}else{
		printf("signal %d\n", sig);
	}
}

int main(int argc, char **argv, char * const envp[])
{
	signal(SIGPIPE, &handlesig);
	signal(SIGCHLD, &handlesig);
	epfd = epoll_create1(EPOLL_CLOEXEC);
	if(epfd == -1) {
		perror("epoll");
		exit(EXIT_FAILURE);
	}
	ev.events = EPOLLIN | EPOLLOUT;
	if(epoll_ctl(epfd, EPOLL_CTL_ADD, fileno(stdin), &ev) == -1) {
		perror("epoll_ctl");
	}

	char buffer[BUF_SIZE];
	for(;;) {
		int nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
		for(int n = 0; n < nfds; ++n) {
			printf("FDs %d: [%d]: %d\n", nfds, n, events[n].data.fd);
			if(events[n].data.fd == fileno(stdin)) {
				// parse spew commands
				int rbytes = read(events[n].data.fd, buffer, BUF_SIZE);
				if(rbytes && rbytes < BUF_SIZE){
					buffer[rbytes] = '\0';
				}
				if(buffer[0] == '\0'){
					continue;
				}
				if (0 == strncmp("EXEC ", buffer, 5)) {
					cmd_exec(buffer+5, envp);
				}
				if (0 == strncmp("WRITE ", buffer, 6)) {
					cmd_write(buffer+6);
				}
				if (0 == strncmp("SIGNAL ", buffer, 7)) {
					cmd_signal(buffer+7);
				}
				if (0 == strncmp("KILL", buffer, 5)) {
					cmd_signal("SIGKILL");
				}
				if (0 == strncmp("TERM", buffer, 5)) {
					cmd_signal("SIGTERM");
				}
			}else{
				int rbytes = read(events[n].data.fd, buffer, BUF_SIZE);
				if(rbytes && rbytes < BUF_SIZE){
					buffer[rbytes] = '\0';
				}
				printf("%s", buffer);
			}
			printf("done %d\n", n);
		}
	}
	printf("EOF\n");
}
void potentialthread() {
	int status;
	if(waitpid(-1, &status, WNOHANG)){
		if(WIFEXITED(status)){
			printf("DIED\n");
		}
	}
}
