/* process handling for spew
 spawn a process
   EXEC /some command
	  <- stdout
		<- stderr
 WRITE blah -> stdout

 signal SIGKILL -> to child
  <- DIED

	- unix socket transport to spew
  - daemonizes to decouple from parent
	- debug mode supports commands on stdin

	Kacper Wysocki, 2015-09-23,
	released under the BSD 2-clause license.
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
	if (TRACE) printf("write '%s'\n", buffer);
	if(!child){
		printf("DEAD\n");
		return -1;
	}
	return write(chin, buffer, strlen(buffer));
}

int cmd_signal(char *buffer){
	if(!child){
		printf("DEAD\n");
		return -1;
	}
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
		child = 0;
	}else{
		printf("signal %d\n", sig);
	}
	fflush(stdout);
	fflush(stderr);
}

int main(int argc, char **argv, char * const envp[])
{
  int i, unixfd;
	char *unixsock = NULL;
	for(i = 1;i < argc; i++){
		if(strncmp(argv[i], "-u", 3) == 0){
			if( i + 1 == argc ){
				fprintf(stderr, "ERROR: not enough args, path to unix socket needed\n");
				exit(EXIT_FAILURE);
			}
			unixsock = argv[i + 1];
			if (TRACE) printf("unix! : %s\n", unixsock);
		}

		if((strncmp(argv[i],"-h", 3) == 0) ||
			 (strncmp(argv[i],"-help", 6) == 0) ||
			 (strncmp(argv[i],"--help", 7) == 0) )
		{
		  printf("usage: spew-exec -u /path/to/unix/socket");

			exit(1);
		}
			
	}

	/* set up epoll */
	signal(SIGPIPE, &handlesig);
	signal(SIGCHLD, &handlesig);
	epfd = epoll_create1(EPOLL_CLOEXEC);
	if(epfd == -1) {
		perror("epoll");
		exit(EXIT_FAILURE);
	}
	struct epoll_event ev;
	

	int oldout, olderr;
	/* set up unix comms */
	if(unixsock) {
		unsigned int us;
		struct sockaddr_un local, remote;
		int len;
		oldout = dup(1);
		olderr = dup(2);
		
		if( (us = socket(AF_UNIX, SOCK_STREAM, 0)) == -1 ){
			perror("socket");
			exit(EXIT_FAILURE);
		}
		local.sun_family = AF_UNIX;
		strcpy(local.sun_path, unixsock);
		unlink(local.sun_path);
		len = strlen(local.sun_path) + sizeof(local.sun_family);
		if(bind(us, (struct sockaddr*) &local, len) == -1){
			perror("bind");
			exit(EXIT_FAILURE);
		}
		if(listen(us, 1) == -1){
			perror("listen");
			exit(EXIT_FAILURE);
		}
		/* daemonize - everything that could go wrong did before this point */
		daemon(1, 1);

		/* continue input on unix socket */
		len = sizeof(struct sockaddr_un);
		if ( (unixfd= accept(us, (struct sockaddr *) &remote, &len)) == -1) {
			perror("accept");
			exit(EXIT_FAILURE);
		}
		if (TRACE) printf("accepted!\n");
		ev.data.fd = unixfd;
		ev.events = EPOLLIN;

		/* stdout and stderr now go on the unix socket */
		dup2(unixfd,1);
		dup2(unixfd,2);

		if(epoll_ctl(epfd, EPOLL_CTL_ADD, unixfd, &ev) == -1) {
			perror("epoll_ctl unixfd");
			exit(EXIT_FAILURE);
		}
	}else{
		if (TRACE) printf("adding stdin\n");
		ev.data.fd = fileno(stdin);
		ev.events = EPOLLIN;
		if(epoll_ctl(epfd, EPOLL_CTL_ADD, fileno(stdin), &ev) == -1) {
			perror("epoll_ctl");
			exit(EXIT_FAILURE);
		}
	}

	char buffer[BUF_SIZE];
	for(;;) {
		int nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
		for(int n = 0; n < nfds; ++n) {
			if (TRACE) printf("FDs %d: [%d]: %d\n", nfds, n, events[n].data.fd);

		  if((unixsock && events[n].data.fd == unixfd) || 
				(!unixsock && events[n].data.fd == fileno(stdin)) ){
				// parse spew commands
				if (TRACE) printf("COMMAND READ..\n");
				int rbytes = read(events[n].data.fd, buffer, BUF_SIZE);
				if (TRACE) printf("read!");
				if(rbytes && rbytes < BUF_SIZE){
					buffer[rbytes] = '\0';
				}
				if(buffer[0] == '\0'){
					continue;
				}
				if (0 == strncmp("EXEC ", buffer, 5)) {
					cmd_exec(buffer+5, envp);
				} else
				if (0 == strncmp("WRITE ", buffer, 6)) {
					cmd_write(buffer+6);
				} else
				if (0 == strncmp("SIGNAL ", buffer, 7)) {
					cmd_signal(buffer+7);
				} else
				if (0 == strncmp("KILL", buffer, 5)) {
					cmd_signal("SIGKILL");
				} else
				if (0 == strncmp("TERM", buffer, 5)) {
					cmd_signal("SIGTERM");
				} else
				if (0 == strncmp("QUIT", buffer, 4) || 0 == strncmp("EXIT", buffer, 4)) {
					exit(0);
				} else {
					fprintf(stderr, "unrecognized command '%s'\n", buffer);
				}
			}else{
				/* read from the child sockets */
				if (TRACE) printf("CHILD SOCKET READ MAAN\n");
				int rbytes = read(events[n].data.fd, buffer, BUF_SIZE);
				if (TRACE) printf("read\n");
				if(rbytes && rbytes < BUF_SIZE){
					buffer[rbytes] = '\0';
				}
				printf("OUT(%lu): %s", rbytes, buffer);
			}
			fflush(stdout);
			fflush(stderr);
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
