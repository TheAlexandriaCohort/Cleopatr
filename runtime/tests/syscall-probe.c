#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %s:%d: %s (errno=%d)\n",__FILE__,__LINE__,#x,errno); exit(1); } } while(0)
static struct sockaddr_in address(const char *ip, int port) { struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(port)}; CHECK(inet_pton(AF_INET,ip,&a.sin_addr)==1); return a; }
static void fullread(int fd, void *out, size_t length) { while(length) { ssize_t n=read(fd,out,length); CHECK(n>0); out=(char*)out+n; length-=n; } }
static void fullwrite(int fd, const void *out, size_t length) { while(length) { ssize_t n=write(fd,out,length); CHECK(n>0); out=(char*)out+n; length-=n; } }
static int connect_to(const char *ip,int port) { int fd=socket(AF_INET,SOCK_STREAM,0); CHECK(fd>=0); struct sockaddr_in a=address(ip,port); CHECK(connect(fd,(void*)&a,sizeof(a))==0); return fd; }
static void dns(int audit, int tcp) {
  unsigned char packet[]={0x12,0x34,1,0,0,1,0,0,0,0,0,0,7,'b','l','o','c','k','e','d',4,'t','e','s','t',0,0,1,0,1};
  int fd=socket(AF_INET,tcp?SOCK_STREAM:SOCK_DGRAM,0); CHECK(fd>=0);
  struct timeval timeout={.tv_sec=5}; CHECK(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))==0);
  struct sockaddr_in a=address("127.0.0.53",53); unsigned char response[4096]; ssize_t n;
  if(tcp) { CHECK(connect(fd,(void*)&a,sizeof(a))==0); unsigned short length=htons(sizeof(packet)); fullwrite(fd,&length,2); fullwrite(fd,packet,sizeof(packet)); fullread(fd,&length,2); n=ntohs(length); CHECK(n<4096); fullread(fd,response,n); }
  else { CHECK(sendto(fd,packet,sizeof(packet),0,(void*)&a,sizeof(a))==sizeof(packet)); n=recvfrom(fd,response,sizeof(response),0,NULL,NULL); }
  CHECK(n>=12); CHECK((response[3]&15)==(audit?0:5)); close(fd);
}
static char pg_read(int fd) { unsigned char header[5]; fullread(fd,header,5); unsigned size; memcpy(&size,header+1,4); size=ntohl(size); CHECK(size>=4&&size<65536); unsigned char body[65536]; fullread(fd,body,size-4); return header[0]; }
static int pg_connect(void) {
  int fd=connect_to("127.0.0.1",19091);
  unsigned char startup[]={0,0,0,0,0,3,0,0,'u','s','e','r',0,'a','g','e','n','t',0,'d','a','t','a','b','a','s','e',0,'t','e','s','t',0,0};
  unsigned size=htonl(sizeof(startup)); memcpy(startup,&size,4); fullwrite(fd,startup,sizeof(startup));
  CHECK(pg_read(fd)=='R'); CHECK(pg_read(fd)=='Z'); return fd;
}
static void pg_query(int fd, const char *sql, int allowed) { unsigned char h[5]={'Q'}; unsigned n=htonl(strlen(sql)+5); memcpy(h+1,&n,4); fullwrite(fd,h,5); fullwrite(fd,sql,strlen(sql)+1); char type=pg_read(fd); CHECK(type==(allowed?'C':'E')); if(allowed) CHECK(pg_read(fd)=='Z'); }
int main(int argc,char **argv) {
  int audit=argc>1&&!strcmp(argv[1],"audit");
  struct stat st; CHECK(stat("/workspace/readonly/data",&st)==0);
  CHECK(chmod("/workspace/readonly/data",0600)==(audit?0:-1));
  CHECK(chmod("/workspace/writable/result",0600)==0);
  CHECK(fstatat(AT_FDCWD,"/workspace/writable/result",&st,0)==0);
  CHECK((st.st_mode&0777)==0600); puts("[PASS] metadata stat and chmod honor policy mode");
  CHECK(setuid(getuid())==0); CHECK(setuid(0)==-1); CHECK(getuid()!=0);
  CHECK(syscall(SYS_unshare,0x10000000)==-1); puts("[PASS] privilege attempts assessed; isolation prevents elevation in Audit and Enforce");
  signal(SIGUSR2,SIG_IGN);
  int child=fork(); CHECK(child>=0); if(!child) { for(;;) pause(); }
  CHECK(kill(child,0)==0); CHECK(kill(child,SIGUSR2)==(audit?0:-1));
  CHECK(syscall(SYS_tgkill,getpid(),syscall(SYS_gettid),0)==0);
  CHECK(kill(1,0)==-1); CHECK(kill(child,SIGTERM)==0); CHECK(waitpid(child,NULL,0)==child);
  puts("[PASS] process and thread signals assessed; enclave init cannot be targeted");
  int fd=socket(AF_INET,SOCK_STREAM,0); CHECK(fd>=0); struct sockaddr_in a=address("127.0.0.1",23456);
  CHECK(bind(fd,(void*)&a,sizeof(a))==(audit?0:-1)); close(fd);
  fd=socket(AF_INET,SOCK_STREAM,0); a=address("127.0.0.1",23457); CHECK(bind(fd,(void*)&a,sizeof(a))==0); CHECK(listen(fd,2)==0);
  child=fork(); CHECK(child>=0); if(!child) { close(fd); int peer=connect_to("127.0.0.1",23457); fullwrite(peer,"x",1); close(peer); _exit(0); }
  int peer=accept(fd,NULL,NULL); CHECK(peer>=0); char byte; fullread(peer,&byte,1); CHECK(byte=='x'); close(peer); close(fd); CHECK(waitpid(child,NULL,0)==child);
  puts("[PASS] network.listen denies protected ports and allows private enclave servers");
  dns(audit,0); dns(audit,1); puts("[PASS] UDP and TCP DNS policy decisions precede responses");
  fd=pg_connect(); pg_query(fd,"SELECT 1",1); pg_query(fd,"SELECT 'blocked'",audit); close(fd);
  fd=pg_connect(); pg_query(fd,"BEGIN",audit); close(fd);
  puts("[PASS] native database route mediates connect, SQL query and transaction");
  puts(audit?"CLEO_ACTIONS_AUDIT_PASSED":"CLEO_ACTIONS_ENFORCE_PASSED"); return 0;
}
