#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include "../include/dirtree.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>

#define MAXMSGLEN 100
#define OFFSETER 100000
//identity code for each operation
#define OPTREE 9
#define OPUNLINK 8
#define OPDIRENTRY 7
#define OPXSTAT 6
#define OPLSEEK 5
#define OPREAD 4
#define OPWRITE 3
#define OPCLOSE 2
#define OPOPEN 1

/*the basic structure for all sent packages
  sent from client */
typedef struct {
  int op;
  int len;
  char buf[0];
} basic_header;

/*small structures specified for each function
  based on the information they want to send*/
typedef struct {
  int pathname_len;
  char data[0];
} getdirtree_type;

typedef struct {
  int fd;
  size_t nbytes;
  off_t basep;
} getentry_type;

typedef struct {
  int pathname_len;
  char data[0];
} unlink_type;

typedef struct {
  int pathname_len;
  int ver;
  char data[0];
} xstat_type;

typedef struct {
  int fd;
  off_t offset;
  int whence;
} lseek_type;

typedef struct {
  int code;
  size_t count;
  char data[0];
} write_type;

typedef struct {
  int code;
  size_t count;
} read_type;

typedef struct{
  int code;
} close_type;

typedef struct {
  int pathname_len;
  int flag;
  mode_t mode;
  char data[0];
} open_type;

int sockfd;

/* this function makes the fd we got by RPC 
  large enough to be distinguished from local fds */
int forward(int fd) {
  return (fd + OFFSETER);
}

/* this function recover the true fd that we have put
  through forward function */
int back(int fd) {
  return (fd - OFFSETER);
}

/* The following line declares a function pointer 
  with the same prototype as the open function.*/
int (*orig_open)(const char *pathname, int flags, ...); 
ssize_t  (*orig_read) (int fd, void *buf, size_t count);
int (*orig_close)(int fd);
ssize_t (*orig_write) (int fd, const void *buf, size_t count);
off_t (*orig_lseek) (int fd, off_t offset, int whence);
int (*orig_stat) (int ver, const char *pathname, struct stat *buf);
int (*orig_unlink) (const char *pathname);
ssize_t (*orig_getdirentries) (int fd, 
                    char *buf, size_t nbytes , off_t *basep);
struct dirtreenode* (*orig_getdirtree) ( char *path );
void (*orig_freedirtree) ( struct dirtreenode* dt );



/* since free operation is aimed at freeing all the local spcaes,
  we do not need to make it an RPC */
void freedirtree( struct dirtreenode* dt ){
  if (dt!=NULL) {
    free(dt->name);
    int i;
    for (i=0; i<dt->num_subdirs; i++) {
      freedirtree(dt->subdirs[i]);
    }
  }
  free(dt->subdirs);
  free(dt);
}

/* prepare the marshall procedure for dirtreenode,
  need to send server the path only, so pack the path and send */
void pack_dirtreenode(const char *path){
  int templen = 1;
  templen += strlen(path);
  void *fake_pack = malloc(templen + 
            sizeof(basic_header) + sizeof(getdirtree_type));
  basic_header *true_pack = (basic_header *)fake_pack;
  true_pack->op = OPTREE;
  true_pack->len = (templen+sizeof(getdirtree_type));
  
  getdirtree_type *close_content = (getdirtree_type *)true_pack->buf;
  close_content->pathname_len = templen;
  memcpy(close_content->data, path, (templen));
  send(sockfd, (char *)true_pack, ((true_pack->len)+sizeof(basic_header)),0);
  free(fake_pack);
}

/* this function construct the tree based on the package send from server,
   and recover the original tree made by the server as the return */
struct dirtreenode* construct_tree(int blank) {
  char buf[MAXMSGLEN+1];
  int rv;
  struct dirtreenode *root = malloc(sizeof(struct dirtreenode));
  rv = recv(sockfd, buf, sizeof(int)+ sizeof(int), 0);
  if (rv<0) err(1,0);
  int templen = *((int *)buf);
  int num_subdirs = *((int *)(buf+sizeof(int)));
  // name of the root
  char *name = malloc(templen);
  rv = recv(sockfd, name, templen, 0);
  root->name = name;
  root->num_subdirs = num_subdirs;
  //malloc space for all the subdirtrees
  struct dirtreenode **temptreearr = 
      malloc(sizeof(struct dirtreenode *) * num_subdirs);
  root->subdirs = temptreearr;
  int i;
  for (i=0; i<num_subdirs; i++) {
    // construct tree recursively for all the subdirs
    temptreearr[i] = construct_tree(i);
  }
  return root;
}

/* main function for getdirtree, marshall and unmarshall the 
  information to and from the server, this function makes a tree
  based on the path and all the files & subdirectories it have*/
struct dirtreenode* getdirtree ( const char *path ){
  char buf[MAXMSGLEN+1];
  char *tempbuf;
  int *tempresult;
	pack_dirtreenode(path); //send information of path to server
  int rv;
	rv = recv(sockfd, buf, sizeof(int)+sizeof(int), 0);	// get message
	if (rv<0) err(1,0);			// in case something went wrong
  int indicator = *(int *)buf;
  //indicator is used for knowing whether the getdirtree function went wrong
  if (indicator == 0) {
    //the function went wrong at the server
    tempbuf = buf+sizeof(int);
    tempresult = (int *)tempbuf;
    //set errno
    errno = *(tempresult);
    return NULL;
  } else {
    //function returns fine
    struct dirtreenode *root = malloc(sizeof(struct dirtreenode));
    rv = recv(sockfd, buf, sizeof(int)+sizeof(int), 0);
    //receive the total size of tree, as well as number of subdirs
    int templen = *((int *)buf);
    int num_subdirs = *((int *)(buf+sizeof(int)));
    char *name = malloc(templen);
    rv = recv(sockfd, name, templen, 0);
    root->name = name;
    root->num_subdirs = num_subdirs;
    struct dirtreenode **temptreearr = 
        malloc(sizeof(struct dirtreenode *) * num_subdirs);
    root->subdirs = temptreearr;
    int i;
    for (i=0; i<num_subdirs; i++) {
      //construct tree for each subdir at first level
      temptreearr[i] = construct_tree(i);
    }
    return root;
  }
}

/* prepare the marshall procedure for direntires,
  need to send server the fd, nbytes & the offset pointer */
void pack_getdirentries(int fd, size_t nbytes, off_t *basep){
  void *fake_pack = malloc(sizeof(basic_header)+sizeof(getentry_type));
  basic_header *true_pack = (basic_header *)fake_pack;
  true_pack->op = OPDIRENTRY;
  true_pack->len = sizeof(getentry_type);
  getentry_type *close_content = (getentry_type *)true_pack->buf;
  close_content->fd = fd;
  close_content->nbytes = nbytes;
  close_content->basep = *basep;
  send(sockfd, (char *)true_pack,((true_pack->len)+sizeof(basic_header)), 0);	
  free(fake_pack);
}

/* main function for getdirentries, call helper to send information
  to server and receive from server to get result, this function gets
  upto nbytes of the direntory entries starts from basep */
ssize_t getdirentries(int fd, char *buff, size_t nbytes , off_t *basep) {
  if (fd >= OFFSETER) {
    fd=back(fd);
  } else  {
    return orig_getdirentries(fd, buff, nbytes, basep);}
  ssize_t result;
  char *tempbuf;
  int *tempresult;
  char buf[MAXMSGLEN+1];
	pack_getdirentries(fd, nbytes, basep); //pack & send to server
	// get message back
  int rv;
 	rv = recv(sockfd, buf,sizeof(ssize_t)+sizeof(int)+sizeof(off_t), 0);
	if (rv<0) err(1,0);
  //cast char* to get result and errno and basep
  result = *(ssize_t *)(buf);
  tempbuf = buf+sizeof(ssize_t);
  tempresult = (int *)tempbuf;
  errno = *(tempresult);
  *basep = *(off_t *)(buf+sizeof(ssize_t)+sizeof(int));
  if (result > 0) {
    //only continue receive result when return value is positive
    rv = recv(sockfd, buff, result,0);
    if (rv<0) err(1,0);
  }
  return result;
}

/* prepare the marshall procedure for unlink,
  only need to send server the pathname */
void pack_unlink(const char *pathname){
  int templen = 1;
  //leave a single space for null terminator
  templen += strlen(pathname);
  void *fake_pack = 
      malloc(templen + sizeof(basic_header) + sizeof(unlink_type));
  basic_header *true_pack = (basic_header *)fake_pack;
  true_pack->op = OPUNLINK;
  true_pack->len = (templen+sizeof(unlink_type));
  unlink_type *close_content = (unlink_type *)true_pack->buf;
  close_content->pathname_len = templen;
  //use memcpy to record the pathname into the package
  memcpy(close_content->data, pathname, (templen));
  send(sockfd, (char *)true_pack,((true_pack->len)+sizeof(basic_header)),0);
  free(fake_pack);
}


/* main function for unlink, call helper to send information
  to server and receive from server to get result, this function
  deletes a name and/or the file it related to*/
int unlink(const char *pathname) {
  int result;
  char *tempbuf;
  int *tempresult;
  char buf[MAXMSGLEN+1];
	pack_unlink(pathname);
	// get message back
  int rv;
	rv = recv(sockfd, buf, sizeof(int)+sizeof(int), 0);
	if (rv<0) err(1,0);
  //cast char *to get return value and errno
  result = *(int *)(buf);
  tempbuf = buf+sizeof(int);
  tempresult = (int *)tempbuf;
  errno = *(tempresult);
  return result;
}


/* prepare the marshall procedure for xstat,
  only need to send server the pathname and version */
void pack_xstat(int ver, const char *pathname){
  int templen = 1;
  //leave a single space for null terminatro
  templen += strlen(pathname);
  void *fake_pack = malloc(templen + 
                sizeof(basic_header) + sizeof(xstat_type));
  basic_header *true_pack = (basic_header *)fake_pack;
  true_pack->op = OPXSTAT;
  true_pack->len = (templen+sizeof(xstat_type));
  xstat_type *close_content = (xstat_type *)true_pack->buf;
  close_content->ver = ver;
  close_content->pathname_len = templen;
  //record the pathname into the package
  memcpy(close_content->data, pathname, (templen));
  send(sockfd, (char *)true_pack, ((true_pack->len)+sizeof(basic_header)),0);	
  free(fake_pack);
}

/* main function for unlink, call helper to send information
  to server and receive from server to get result, this function
  gets the information of a file and record it in buf*/
int __xstat(int ver, const char *pathname, struct stat *buff) {
  int result;
  int *tempresult;
  char *tempbuf;
  char buf[MAXMSGLEN+1];
	pack_xstat(ver, pathname);
	// get message back
  int rv;
	rv = recv(sockfd, buf, (sizeof(int)+sizeof(int)), 0);	// get message
	if (rv<0) err(1,0);			// in case something went wrong
  //parse the return package char* to unmarshall
  result = *((int *)buf);
  tempbuf = buf+sizeof(int);
  tempresult = (int *)tempbuf;
  errno = *(tempresult);
  rv = recv(sockfd, buff, sizeof(struct stat),0);
  return result;
}

/* prepare the marshall procedure for lseek,
  need to send server the fd, offset and whence */
void pack_lseek(int fd, off_t offset, int whence){
  void *fake_pack = malloc(sizeof(basic_header)+sizeof(lseek_type));
  basic_header *true_pack = (basic_header *)fake_pack;
  true_pack->op = OPLSEEK;
  true_pack->len = sizeof(lseek_type);
  //the inner type
  lseek_type *close_content = (lseek_type *)true_pack->buf;
  close_content->fd = fd;
  close_content->offset = offset;
  close_content->whence = whence;
  send(sockfd, (char *)true_pack,((true_pack->len)+sizeof(basic_header)),0);
  free(fake_pack);
}

/* the main function for lseek, it repositions the offset 
    of the open file associated with the file descriptor*/
off_t lseek(int fd, off_t offset, int whence) {
  //since it has fd, we first decide whether it's local or rpc
  if (fd >= OFFSETER) {
    fd=back(fd);
  } else  {
    //if local, just call lseek locally
    return orig_lseek(fd, offset, whence);}
  off_t result;
  int *tempresult;
  char *tempbuf;
  char buf[MAXMSGLEN+1];
	pack_lseek(fd, offset,whence);
	// get message back
  int rv;
	rv = recv(sockfd, buf, (sizeof(off_t)+sizeof(int)+sizeof(char)), 0);
	if (rv<0) err(1,0);			// in case something went wrong
  //parse return char* to set result and errno
  tempbuf = buf+sizeof(off_t);
  tempresult = (int *)tempbuf;
  errno = *(tempresult);
  result = *((off_t *)buf);
  return result;
}


/* prepare the marshall procedure for write,
  need to send server the fd and count and the content to write */
void pack_write(int fd, void *buf, size_t count) {
  void *fake_pack = malloc(sizeof(basic_header)+sizeof(write_type)+count);
  basic_header *true_pack = (basic_header *)fake_pack;
  true_pack->op = OPWRITE;
  true_pack->len = sizeof(write_type)+count;
  write_type *close_content = (write_type *)true_pack->buf;
  close_content->code = fd;
  close_content->count = count;
  //record the content to write into the package
  memcpy((char *)(close_content->data), buf, count);
  send(sockfd, (char *)true_pack, (sizeof(basic_header)+true_pack->len), 0);
  free(fake_pack);
}

/*the main function for write, it writes up to count size of information
  into the file*/
ssize_t write (int fd, const void *buff, size_t count){
  //since it has fd, we first decide whether it is local or RPC
  if (fd >= OFFSETER) {
    fd=back(fd);
  } else  {
    //if local, just call write locally
    return orig_write(fd, buff, count);}
  ssize_t result;
  int *tempresult;
  char *tempbuf;
  char buf[MAXMSGLEN+1];
  pack_write(fd, buff, count);
	// send message; should check return value
	// get message back
  int rv;
	rv = recv(sockfd, buf,(sizeof(int)+sizeof(ssize_t)), MSG_WAITALL);
	if (rv<0) err(1,0);			// in case something went wrong
	buf[rv]=0;				// null terminate string to print
  //parse return char* to get result and errno
  tempbuf = buf+sizeof(ssize_t);
  tempresult = (int *)tempbuf;
  errno = *(tempresult);
  result = *((ssize_t *)buf);
  return result;
}

/* prepare the marshall procedure for read,
  need to send server the fd and count to read on */
void pack_read(int fd, void *buf, size_t count) {
  void *fake_pack = malloc(sizeof(basic_header)+sizeof(read_type));
  basic_header *true_pack = (basic_header *)fake_pack;
  true_pack->op = OPREAD;
  true_pack->len = sizeof(read_type);
  read_type *close_content = (read_type *)true_pack->buf;
  close_content->code = fd;
  close_content->count = count;
  send(sockfd, (char *)true_pack, (sizeof(basic_header)+true_pack->len), 0);
  free(fake_pack);
}

/*the main function for read operation, it reads the content
  from a file into buff for count amount*/
ssize_t  read(int fd, void *buff, size_t count){
  //since it has fd, we first decide whether it is local or RPC
  if (fd >= OFFSETER) {
    fd=back(fd);
  } else  {
    //if not PRC, just call read locally
    return orig_read(fd, buff, count);}
  ssize_t result;
  int indicator;
  //to indicator whether read succeeds or not on server side
  int *tempresult;
  char *tempbuf;
  char buf[MAXMSGLEN+1];
  pack_read(fd, buff, count);
	// send message; should check return value
	// get message back
  int rv;
  //first only receive a single indicator
	rv = recv(sockfd, buf,sizeof(int), MSG_WAITALL);	// get message
	if (rv<0) err(1,0);			// in case something went wrong
  indicator = *(int *)(buf);
  if (indicator  < 1) {
  // read fail on server side
  //when error, total package size is indicator + read_result + errno
    rv = recv(sockfd, buf, (sizeof(ssize_t)+sizeof(int)), MSG_WAITALL);
    if (rv<0) err(1,0);	
    tempbuf = buf+sizeof(ssize_t);
    tempresult = (int *)tempbuf;
    errno = *(tempresult);
    result = *((ssize_t *)buf);
    return result;
  } else {
  //no error: indicator + read_result + errno + data of size read_result
    rv = recv(sockfd, buf, (sizeof(ssize_t)+sizeof(int)), MSG_WAITALL);
    if (rv<0) err(1,0);
    result = *((ssize_t *)buf);
    tempbuf = buf+sizeof(ssize_t);
    tempresult = (int *)tempbuf;
    errno = *(tempresult);
    if (result!= 0) rv = recv(sockfd, buff, result, MSG_WAITALL);
    //here we use waitall flag to make sure that we receive all the content
    return result;
  }
}

/* prepare the marshall procedure for close,
  only need to send server the fd */
void pack_close_send(int fd){
  void *fake_pack = malloc(sizeof(basic_header)+sizeof(close_type));
  basic_header *true_pack = (basic_header *)fake_pack;
  true_pack->op = OPCLOSE;
  true_pack->len = sizeof(close_type);
  close_type *close_content = (close_type *)true_pack->buf;
  close_content->code = fd;
  send(sockfd, (char *)true_pack,((true_pack->len)+sizeof(basic_header)),0);
  free(fake_pack);
}

/*main function for close, which closes a file descriptor*/
int close(int fd) {
  if (fd >= OFFSETER) {
    //since it has fd, we need to check whether it's rpc or local
    fd=back(fd);
  } else  {
    // if local, just call close locally
    return orig_close(fd);}
  int result;
  char *tempbuf;
  int *tempresult;
  char buf[MAXMSGLEN+1];
  pack_close_send(fd);
	// send message; should check return value
	// get message back
  int rv;
	rv = recv(sockfd, buf, (sizeof(int)+sizeof(int)), 0);	// get message
	if (rv<0) err(1,0);			// in case something went wrong
	buf[rv]=0;				// null terminate string to print
	//parse resulted char* to result and errno
  tempbuf = buf + sizeof(int);
  tempresult = (int *)tempbuf;
  errno = *tempresult;
  result = *((int*)(buf));
	return result;
}

/* prepare the marshall procedure for open,
  need to include pathname, flags and mode */
void pack_open_send(const char *pathname, int flags, mode_t m){
  int templen = 1;
  //leave a single space for null terminator 
  templen += strlen(pathname);
  void *fake_pack = malloc(templen+sizeof(basic_header)+sizeof(open_type));
  basic_header *true_pack = (basic_header *)fake_pack;
  true_pack->op = OPOPEN;
  true_pack->len = (templen+sizeof(open_type));
  //cast the smaller char* in large struct to small struct for opentype
  open_type *open_content = (open_type *)true_pack->buf;
  open_content->flag = flags;
  open_content->mode = m;
  open_content->pathname_len = templen;
  //record the pathname to the package we need to send
  memcpy(open_content->data, pathname, (templen));
  send(sockfd, (char *)true_pack, ((true_pack->len)+sizeof(basic_header)),0);
  free(fake_pack);
}



/*main function for open, returns a file descriptor based on the
  pathname we gave*/
int open(const char *pathname, int flags, ...) {
  int result;
  char *tempbuf;
  int *tempresult;
  char buf[MAXMSGLEN+1];
	mode_t m=0;
  // the sample code for getting mode
	if (flags & O_CREAT) {
		va_list a;
		va_start(a, flags);
		m = va_arg(a, mode_t);
		va_end(a);
	}
  pack_open_send(pathname, flags, m);
	// send message; should check return value
	// get message back
  int rv;
	rv = recv(sockfd, buf, (sizeof(int)+sizeof(int)), 0);	// get message
	if (rv<0) err(1,0);			// in case something went wrong
	buf[rv]=0;				// null terminate string to print
  //parse the returned char* to int to indicate result and errno
  tempbuf = buf + sizeof(int);
  tempresult = (int *)tempbuf;
  errno = *tempresult;
  result = *(int*)(buf);
  //if error happens, leave the error unchanged
  if (result < 0) return result;
  //since all fd are from server, need to indicate them as rpc fds
  result = forward(result);
	return result;
}



// This function is automatically called when program is started
void _init(void) {
	// set function pointer orig_open to point to the original open function
	orig_open = dlsym(RTLD_NEXT, "open");
  orig_read = dlsym(RTLD_NEXT, "read");
  orig_close = dlsym(RTLD_NEXT, "close");
  orig_write = dlsym(RTLD_NEXT, "write");
  orig_lseek = dlsym(RTLD_NEXT, "lseek");
  orig_stat = dlsym(RTLD_NEXT, "__xstat");
  orig_unlink = dlsym(RTLD_NEXT, "unlink");
  orig_getdirentries = dlsym(RTLD_NEXT, "getdirentries");
  orig_getdirtree = dlsym(RTLD_NEXT, "getdirtree");
  orig_freedirtree = dlsym(RTLD_NEXT, "freedirtree");
	//fprintf(stderr, "Init mylib\n");
 
	char *serverip;
	char *serverport;
	unsigned short port;
	int rv;
	struct sockaddr_in srv;
	
	// Get environment variable indicating the ip address of the server
	serverip = getenv("server15440");
	if (serverip) {
    //printf("Got environment variable server15440: %s\n", serverip);
   }	else {
  //printf("Environment variable server15440 not found.  Using 127.0.0.1\n");
		serverip = "127.0.0.1";
	}
	
	// Get environment variable indicating the port of the server
	serverport = getenv("serverport15440");
	if (serverport) {
//fprintf(stderr,"Got environment variable serverport15440: %s\n",serverport);
	} else {
		serverport = "12768";
	}
	port = (unsigned short)atoi(serverport);
	
	// Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);	// TCP/IP socket
	if (sockfd<0) err(1, 0);			// in case of error
	
	// setup address structure to point to server
	memset(&srv, 0, sizeof(srv));			// clear it first
	srv.sin_family = AF_INET;			// IP family
	srv.sin_addr.s_addr = inet_addr(serverip);	// IP address of server
	srv.sin_port = htons(port);			// server port

	// actually connect to the server
	rv = connect(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
	if (rv<0) err(1,0);
}

//close socket in _fini
void _fini(void) {
  orig_close(sockfd);
}