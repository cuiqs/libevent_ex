#include <event2/dns.h>
#include <event2/dns_struct.h>
#include <event2/util.h>
#include <event2/event.h>

#include <sys/socket.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>

#define LISTEN_PORT 15353

#define LOCALHOST_IPV4_ARPA "1.0.0.127.in-addr.arpa"
#define LOCALHOST_IPV6_ARPA ("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa")

const ev_uint8_t LOCALHOST_IPV4[]={127,0,0,1};
const ev_uint8_t LOCALHOST_IPV6[]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};

#define TTL 4242

void server_callback(struct evdns_server_request *request,void *data)
{
	int i;
	int error=DNS_ERR_NONE;

	for(int i=0;i<request->nquestions;++i)
	{
		const struct evdns_server_question *q=request->questions[i];
		int ok=-1;

		if(0==evutil_ascii_strcasecmp(q->name,"localhost"))
		{
			if(q->type==EVDNS_TYPE_A)
				ok=evdns_server_request_add_a_reply(request,q->name,1,LOCALHOST_IPV4,TTL);
			else if(q->type==EVDNS_TYPE_AAAA)
				ok=evdns_server_request_add_aaaa_reply(request,q->name,1,LOCALHOST_IPV6,TTL);
		}
		else if(evutil_ascii_strcasecmp(q->name,LOCALHOST_IPV4_ARPA))
		{
			if(q->type==EVDNS_TYPE_PTR)
				ok=evdns_server_request_add_ptr_reply(request,NULL,q->name,"LOCALHOST",TTL);
		}
		else if(evutil_ascii_strcasecmp(q->name,LOCALHOST_IPV6_ARPA))
		{
			if(q->type==EVDNS_TYPE_PTR)
				ok=evdns_server_request_add_ptr_reply(request,NULL,q->name,"LOCALHOST",TTL);
		}
		else
			error=DNS_ERR_NOTEXIST;
		if(ok<0 && error==DNS_ERR_NONE)
			error=DNS_ERR_SERVERFAILED;
	}
	evdns_server_request_respond(request,error);
}


int main(int argc,char *argv[])
{
	struct event_base *base;
	struct evdns_server_port *server;
	evutil_socket_t server_fd;
	struct sockaddr_in listenaddr;

	base=event_base_new();
	if(!base)
		return 1;

	server_fd=socket(AF_INET,SOCK_DGRAM,0);
	if(server_fd<0)
		return 1;
	memset(&listenaddr,0,sizeof(listenaddr));
	listenaddr.sin_family=AF_INET;
	listenaddr.sin_port=htons(LISTEN_PORT);
	listenaddr.sin_addr.s_addr=INADDR_ANY;
	if(bind(server_fd,(struct sockaddr *)&listenaddr,sizeof(listenaddr))<0)
		return 1;

	server=evdns_add_server_port_with_base(base,server_fd,0,server_callback,NULL);
	event_base_dispatch(base);
	
	evdns_close_server_port(server);
	event_base_free(base);

	return 0;
}
