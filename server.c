#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include "../include/dirtree.h"

#define MAXMSGLEN 100

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
  int flag;
  mode_t mode;
  char data[0];
} open_type;

typedef struct{
  int code;
} close_type;

typedef struct {
  int code;
  size_t count;
  char data[0];
} read_type;

typedef struct {
  int code;
  size_t count;
  char data[0];
} write_type;

typedef struct {
  int fd;
  off_t offset;
  int whence;
} lseek_type;

typedef struct {
  int pathname_len;
  int ver;
  char data[0];
} xstat_type;

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
  char data[0];
} getdirtree_type;

/* call open on server side, and pack the result to send back
  to client */
void new_open(void *pack,int sessfd) {
  int len, flags, open_result;
  mode_t mode;
  //cast to the proper small struct type
  open_type *true_pack = (open_type *)pack;
  len = true_pack->pathname_len;
  mode = true_pack->mode;
  flags = true_pack->flag;
  char *data = malloc(len);
  //get space to store the pathname
  memcpy(data, true_pack->data, len);
  open_result = open(data, flags, mode);
  //result size+errno size
  int return_packsize = sizeof(int)+sizeof(int);
  void *return_pack = malloc(return_packsize);
  //copy integer using memcpy by taking address
  memcpy(return_pack, &open_result, sizeof(int));
  memcpy(return_pack+sizeof(int), &errno, sizeof(int));
  send(sessfd, return_pack, return_packsize,0);
  free(data);
  free(return_pack);
}

/* call close on server side, and pack the result to send back
  to client */
void new_close(void *pack, int sessfd) {
  int fd, close_result;
  //cast to the proper small struct type
  close_type *true_pack = (close_type *)pack;
  fd = true_pack->code;
  close_result = close(fd);
  //return size = result size + errno size
  void *return_pack = malloc(sizeof(int)+sizeof(int));
  memcpy(return_pack, &close_result, sizeof(int));
  //copy integer using memcpy by taking address
  memcpy(return_pack+sizeof(int), &errno, sizeof(int));
  send(sessfd, return_pack, (sizeof(int)+sizeof(int)),0);
  free(return_pack);
}

/* call write on server side, and pack the result to send back
  to client */
void new_write(void *pack, int sessfd) {
  int fd, count;
  ssize_t write_result;
  //cast to the proper small struct type
  write_type *true_pack = (write_type *)pack;
  fd = true_pack->code;
  count = true_pack->count;
  write_result = write(fd, true_pack->data, count);
  //return size = result size + errno size
  void *return_pack = malloc(sizeof(write_result)+sizeof(int));
  //copy integer using memcpy by taking address
  memcpy(return_pack, &write_result, sizeof(write_result));
  memcpy(return_pack+sizeof(write_result), &errno, sizeof(int));
  send(sessfd, return_pack, (sizeof(write_result)+sizeof(int)),0);
  free(return_pack);
}


/* call __xstat on server side, and pack the result to send back
  to client */
void new_xstat(void *pack, int sessfd) {
  int ver, xstat_result;
  int pathname_len;
  //the information storer
  struct stat temp;
  //cast to the proper small struct type
  xstat_type *true_pack = (xstat_type *)pack;
  pathname_len = true_pack->pathname_len;
  ver = true_pack->ver;
  char *data = malloc(pathname_len);
  //know how much space to alloc from the length of pathname
  memcpy(data, true_pack->data, pathname_len);
  xstat_result = __xstat(ver, data, &temp);
  //return size = result size + errno size + information size
  void *return_pack = malloc(sizeof(int)+sizeof(int)+sizeof(struct stat));
  *((int *)return_pack) = xstat_result;
  //copy integer using memcpy by taking address
  memcpy(return_pack+sizeof(int), &errno, sizeof(int));
  //again, copy using memcpy by taking address
  memcpy(return_pack+sizeof(int)+sizeof(int), &temp, sizeof(struct stat));
  send(sessfd, return_pack, (sizeof(int)+sizeof(int)+sizeof(struct stat)),0);
  free(return_pack);
  free(data);
}

/*call unlink on server side, and pack the result to send back
  to client*/
void new_unlink(void *pack, int sessfd) {
  int unlink_result;
  int pathname_len;
  //cast to the proper small struct type
  unlink_type *true_pack = (unlink_type *)pack;
  pathname_len = true_pack->pathname_len;
  //know how many space need to alloc to store the data from
  //pathlen information sent by client
  char *data = malloc(pathname_len);
  memcpy(data, true_pack->data, pathname_len);
  unlink_result = unlink(data);
  //return size = result size + errno size
  void *return_pack = malloc(sizeof(int)+sizeof(int));
  *((int *)return_pack) = unlink_result;
  memcpy(return_pack+sizeof(int), &errno,sizeof(int));
  send(sessfd, return_pack, (sizeof(int)+sizeof(int)),0);
  free(data);
  free(return_pack);
}
/*call read on server side, and pack the result as well as the
  content to send back to client*/
void new_read(void *pack, int sessfd) {
  int fd, count;
  ssize_t read_result;
  read_type *true_pack = (read_type *)pack;
  fd = true_pack->code;
  count = true_pack->count;
  //first malloc a potentially larger space, to make sure
  //all the read content can be stored
  char *tempbuf = malloc(count);
  read_result = read(fd, tempbuf, count);
  if (read_result < 0) {
    //error happend
    int indicator = 0;
    //indicating read failed on server side
    //return size = indicator size + result size + errno size
    void *return_pack = malloc(sizeof(int)+sizeof(read_result)+sizeof(int));
    //copy integer using memcpy by taking address
    memcpy(return_pack, &indicator, sizeof(int));
    memcpy(return_pack+sizeof(int), &read_result, sizeof(read_result));
    memcpy(return_pack+sizeof(read_result)+sizeof(int), &errno, sizeof(int));
    send(sessfd, return_pack, 
      (sizeof(read_result)+sizeof(int)+sizeof(int)),0);
    free(tempbuf);
    free(return_pack);
  } else {
    //read succeed
    int indicator2 = 1;
    //return size = indicator size+result size+errno size+ how much is read
    void *return_pack = 
      malloc(sizeof(int)+sizeof(read_result)+sizeof(int)+read_result);
    // if no error happen, use 1 as the indicator
    memcpy(return_pack, &indicator2, sizeof(int));
    //copy integer using memcpy by taking address
    memcpy(return_pack+sizeof(int), &read_result, sizeof(read_result));
    memcpy(return_pack+sizeof(read_result)+sizeof(int), &errno, sizeof(int));
    //record the read content into package according to the result value
    memcpy(return_pack+sizeof(read_result)+sizeof(int)+sizeof(int),
        tempbuf, read_result);
    send(sessfd, return_pack, 
        (sizeof(read_result)+sizeof(int)+sizeof(int)+read_result),0);
    free(tempbuf);
    free(return_pack);
  }
}

/*call lseek on server side, and pack the result to send back to client*/
void new_lseek(void *pack, int sessfd) {
  int fd, whence;
  off_t lseek_result, offset;
  //cast to the proper small struct type
  lseek_type *true_pack = (lseek_type *)pack;
  fd = true_pack->fd;
  whence = true_pack->whence;
  offset = true_pack->offset;
  lseek_result = lseek(fd,offset, whence);
  //return size = result size+errno size+null terminator
  void *return_pack = malloc(sizeof(off_t)+sizeof(int)+sizeof(char));
  memcpy(return_pack, &lseek_result, sizeof(off_t));
  //copy result using memcpy by taking address
  memcpy(return_pack+sizeof(off_t), &errno, sizeof(int));
  *((char *)return_pack+sizeof(off_t)+sizeof(int)) = 0;
  send(sessfd, return_pack, (sizeof(off_t)+sizeof(int)+sizeof(char)),0);
  free(return_pack);
}

/*call getdirentries on server side, 
  and pack the result, as well as the content and the changed basep,
  to send back to client*/
void new_getdirentries(void *pack, int sessfd) {
  int fd;
  size_t nbytes;
  ssize_t getentry_result;
  //for storing the chaged basep
  off_t *basep = malloc(sizeof(off_t));
  //cast to the proper small struct type
  getentry_type *true_pack = (getentry_type *)pack;
  fd = true_pack->fd;
  nbytes = true_pack->nbytes;
  *basep = true_pack->basep;
  
  char *buf = malloc(nbytes);
  getentry_result = getdirentries(fd, buf, nbytes, basep);

  if (getentry_result >= 0) {
  //good, getdirentries succeed
  //return size=result size+errno size+basep size+content size
    void *return_pack = 
      malloc(sizeof(ssize_t)+sizeof(int)+sizeof(off_t)+getentry_result);
    //copy result using memcpy by taking address
    memcpy(return_pack, &getentry_result, sizeof(ssize_t));
    //copy integer using memcpy by taking address
    memcpy(return_pack+sizeof(ssize_t), &errno, sizeof(int));
    //copy basep using memcpy by taking address
    memcpy(return_pack+sizeof(ssize_t)+sizeof(int), basep, sizeof(off_t));
    //copy content to string
    memcpy(return_pack+sizeof(ssize_t)+sizeof(int)+sizeof(off_t), 
      buf, getentry_result);
    send(sessfd, return_pack, 
      sizeof(ssize_t)+sizeof(int)+sizeof(off_t)+getentry_result,0);
    free(return_pack);
  } else {
    // error happened in getdirentries
    // now return size = result size + errno size + basep size
    void *return_pack = malloc(sizeof(ssize_t)+sizeof(int)+sizeof(off_t));
    memcpy(return_pack, &getentry_result, sizeof(ssize_t));
    memcpy(return_pack+sizeof(ssize_t), &errno, sizeof(int));
    memcpy(return_pack+sizeof(ssize_t)+sizeof(int), basep, sizeof(off_t));
    send(sessfd, return_pack, sizeof(ssize_t)+sizeof(int)+sizeof(off_t),0);
    free(return_pack);
  }
  free(basep);
  free(buf);
}

/*step through the whole tree recursively to get the size of the whole tree*/
int get_treesize(struct dirtreenode * root) {
  int size_sofar = sizeof(int)+sizeof(int);
  int i;
  int lenR = strlen(root->name)+1;
  size_sofar += lenR;
  int num_subdirs = root->num_subdirs;
  for (i=0; i<num_subdirs; i++) {
    //recursively go into every branches
    size_sofar += get_treesize(root->subdirs[i]);
  }
  return size_sofar;
}

/* the basic idea is to DFS through the whole tree,
  and put nodes information into the package in order*/
void pack_treetostr(void *return_pack,
       struct dirtreenode *root, int *counter) {
  int size_temp = strlen(root->name)+1;
  //leave a space for null terminator
  //the counter is used to record how much space we have covered so far
  memcpy(return_pack+(*counter), &size_temp, sizeof(int));
  //the first information is the length of root name
  *counter+=sizeof(int);
  //second information is the number of subdirs
  int num_subdirs = root->num_subdirs;
  memcpy(return_pack+(*counter), &num_subdirs, sizeof(int));
  *counter+=sizeof(int);
  //last of all, copy pathname into the package
  memcpy(return_pack+(*counter), root->name, size_temp);
  *counter+=size_temp;
  int i;
  for (i=0; i<num_subdirs; i++) {
    //call pack recursively in DFS style
    pack_treetostr(return_pack, root->subdirs[i], counter);
  }
}

/*call getdirentree on server side, 
  and pack the tree into readable string that can be reconstructd by client,
  and send back to client*/
void new_getdirtree(void *pack, int sessfd) {
  struct dirtreenode *getdirtree_result;
  int pathname_len;
  //cast to proper small struct
  getdirtree_type *true_pack = (getdirtree_type *)pack;
  pathname_len = true_pack->pathname_len;
  //alloc space to store the root information given from client
  char *data = malloc(pathname_len);
  memcpy(data, true_pack->data, pathname_len);
  getdirtree_result = getdirtree(data);
  if (getdirtree_result == NULL) {
    //if error happens:
    //return size = indicator + errno size
    void *return_pack = malloc(sizeof(int)+sizeof(int));
    //set the indicator to 0, indicator failure
    *((int *)return_pack) = 0;
    memcpy(return_pack+sizeof(int), &errno,sizeof(int));
    send(sessfd, return_pack, (sizeof(int)+sizeof(int)),0);
    free(return_pack);
  } else {
    //good, return a tree safely
    //the pointer for tracing the size that have been handle so far
    int *counter = malloc(sizeof(int));
    //first, give space for the indicator as well as total tree size
    *counter = sizeof(int)+sizeof(int);
    //get total tree size
    int tree_size = get_treesize(getdirtree_result);
    void *return_pack = malloc(sizeof(int)+sizeof(int)+tree_size);
    //indicator set
    *((int *)return_pack) = 1;
    //total tree size included
    *((int *)(return_pack+sizeof(int))) = tree_size;
    //pack the whole tree into the package
    pack_treetostr(return_pack, getdirtree_result, counter);
    send(sessfd, return_pack, tree_size+sizeof(int)+sizeof(int),0);
    free(return_pack);
    free(counter);
    freedirtree(getdirtree_result);
  }
  free(data);

}


int main(int argc, char**argv) {
	char buf[MAXMSGLEN+1];
	char *serverport;
	unsigned short port;
	int sockfd, sessfd, rv, cv;
	struct sockaddr_in srv, cli;
	socklen_t sa_size;
	
	// Get environment variable indicating the port of the server
	serverport = getenv("serverport15440");
	if (serverport) port = (unsigned short)atoi(serverport);
	else port=12768;

	
	// Create socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);	// TCP/IP socket
	if (sockfd<0) err(1, 0);			// in case of error
	
	// setup address structure to indicate server port
	memset(&srv, 0, sizeof(srv));			// clear it first
	srv.sin_family = AF_INET;			// IP family
	srv.sin_addr.s_addr = htonl(INADDR_ANY);	// don't care IP address
	srv.sin_port = htons(port);			// server port

	// bind to our port
	rv = bind(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
	if (rv<0) err(1,0);
	
	// start listening for connections
	rv = listen(sockfd, 5);
	if (rv<0) err(1,0);
	
	// main server loop
	while(1) {
		sa_size = sizeof(struct sockaddr_in);
		sessfd = accept(sockfd, (struct sockaddr *)&cli, &sa_size);
		if (sessfd<0) err(1,0);
    //fork to handle multi cients
		cv = fork();
    if (cv == 0) {
      close(sockfd);
		// get messages and send replies to this client
		while ( (rv=recv(sessfd, buf, sizeof(basic_header), 0)) > 0) {
      //first just receive the basic_header size, in order to know
      //the total amount of information sent by client
      basic_header *package = malloc(sizeof(basic_header));
			buf[rv]=0;		// null terminate string to print
			memcpy(package, buf, sizeof(basic_header));
      //get total length sent by server
      int inner_len = package->len;
      
      void *inner_pack = malloc(inner_len);
      //use WAITALL flag to receive all information
      recv(sessfd, inner_pack, inner_len,MSG_WAITALL);

      //enter different handle function based on operation code
      if(package->op == OPOPEN) {
          new_open(inner_pack, sessfd);
      } else if (package->op == OPCLOSE) {
          new_close(inner_pack, sessfd);
      } else if (package->op == OPWRITE) {
          new_write(inner_pack,sessfd);
      } else if (package->op == OPREAD) {
          new_read(inner_pack,sessfd);
      } else if (package->op == OPLSEEK) {
          new_lseek(inner_pack, sessfd);
      } else if (package->op == OPXSTAT) {
          new_xstat(inner_pack, sessfd);
      } else if (package->op == OPDIRENTRY) {
          new_getdirentries(inner_pack, sessfd);
      } else if (package->op == OPUNLINK) {
          new_unlink(inner_pack, sessfd);
      } else if (package->op == OPTREE) {
          new_getdirtree(inner_pack, sessfd); }
      free(inner_pack);
      free(package);  
		}
		// either client closed connection, or error
		if (rv<0) err(1,0);
		close(sessfd);
   exit(0);
	}
 }
	// close socket
	close(sessfd);

	return 0;
}

