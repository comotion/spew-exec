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
#include <unistd.h>
#include <sys/stat.h>
#include <error.h>
#include <errno.h>
#include <sys/wait.h>

#define BUF_SIZE 1024

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

// global var of the executed child
pid_t child;
int chin, chout;

int tok_args(char *args, char **argv)
{
	int i = 0;
	char *p;
	while( (p = strchr(args, ' ')) != NULL){
		argv[i++] = p + 1;
	  *p = '\0';
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
	if(0 != stat(path, &statbuf) || !S_ISREG(statbuf.st_mode) || !( S_IXUSR & statbuf.st_mode )){
			printf("Couldn't execute %s: %s\n", path, strerror(errno));
			exit(2);
	}
	parsedargs[0] = path;
	parsedargs[1] = NULL;
	if(args != NULL) 
		tok_args(args, parsedargs +1);

	// we need fd's to child to send stdin and capture stdout?
	int outfd[2];
	int infd[2];
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
		close(0);
		// close(1); close(2);
		close(infd[1]); // child only reads from infd
		close(outfd[0]); // child only writes to outfd
		dup(infd[0]); // child stdin from inpipe
		//dup(outfd[1]); // stdout
		//dup(outfd[1]); // stderr
		printf("wuttf");

		int rc = execve(path, parsedargs, envp);
		perror("execution failed");
	}else{ // parent
		char buf[1024]; 
		// parent writes to   infd
		// parent reads  from outfd
		chin = infd[1];
		chout = outfd[0];
		close(infd[0]); 
		close(outfd[1]); 
		/*
		while(!feof(stdin)){
			fgets(buf, sizeof(buf), stdin);
			write(infd[1], buf, strlen(buf)+1);
			read(outfd[0], buf, 20);
			printf("%s", buf);
		}
		*/
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
	}else{
		printf("signal %d\n", sig);
	}
}

int main(int argc, char **argv, char * const envp[])
{
	signal(SIGPIPE, &handlesig);
	// XXX: select read from various sources: running exec fd's and controlling program, 0mq..
	char buffer[BUF_SIZE];
	while(!feof(stdin)) {
		int status;
		fgets(buffer, sizeof(buffer), stdin);
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
		if(waitpid(-1, &status, WNOHANG)){
			if(WIFEXITED(status)){
				printf("DIED\n");
			}
		}
	}
	printf("EOF\n");
}
