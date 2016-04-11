#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sysinfo.h> /* get_nprocs(void) */
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>

/*
#include dpdk head files
*/
#include "daq_api.h"
#define P_RING "PacketRing"
#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#ifdef HAVE_REDIS
#include "hiredis/hiredis.h"
#endif

#define DAQ_DPDK_VERSION 1

typedef struct _dpdk_context
{
	int stream;
	int fd;

	int breakloop;
	int start;
	int snaplen;
	char name[128];
	char errbuf[128];

	struct timeval timeout;
	struct timeval poll;//maybe useless.

	DAQ_Analysis_Func_t analysis_func;
	DAQ_Stats_t stats;
	DAQ_State state;

	//dpdk val

	struct rte_ring *r;//ring of mempool, may not use.
	struct rte_mempool *mbuf_pool;//maybe useless, capture packets don't need this val.
	unsigned nb_ports;
	
	//the content for dpdk used in this daq model.
} Dpdk_Context_t;

//the dpdk init func
static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN, },
};

static struct ipv4_hdr * mbufToIP(struct rte_mbuf * buf){
	return (struct ipv4_hdr *)rte_pktmbuf_adj(buf, (uint16_t)sizeof(struct ether_hdr));
}


static int initRing(struct rte_ring * r, const char * name, int ring_size, int socket_id){

	//if (_r == NULL)
	r = rte_ring_create(name, ring_size, socket_id, 0);//
	if (r == NULL)
		return -1;//
	if (rte_ring_lookup(name) != r){
		printf("Can not lookup ring from its name.\n");
		return -1;
	}
	return 0;
}


static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;

	if (port >= rte_eth_dev_count())
		return -1;

	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (retval < 0)
			return retval;
	}

	retval  = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	struct ether_addr addr;

	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02"PRIx8" %02"PRIx8" %02"PRIx8
			" %02"PRIx8" %02"PRIx8" %02"PRIx8"\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	rte_eth_promiscuous_enable(port);
	//rte_eth_add_rx_callback(port, 0, add_timestamps, NULL);
	//rte_eth_add_tx_callback(port, 0, calc_latency, NULL);

	return 0;
}


/*Main fuction, init dpdk and call the send packet functions*/
static int  initDPDK(void * handle, int argc, char * argv[]){
	
	uint8_t portid;
	/*init eal*/
	Dpdk_Context_t *ctx = (Dpdk_Context_t *)handle;
	int ret = rte_eal_init(argc,argv);

	if(ret < 0)
		rte_exit(EXIT_FAILURE,"Error with initialization.\n");
	argc -= ret;
	argv += ret;

	ctx->nb_ports = rte_eth_dev_count();
	if (nb_ports < 2 || (ctx->nb_ports  & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	ctx->mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
		NUM_MBUFS * ctx->nb_ports, MBUF_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (ctx->mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* initialize all ports */
	for (portid = 0; portid < ctx->nb_ports; portid++)
		if (port_init(portid, ctx->mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8"\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too much enabled lcores - "
			"App uses only 1 lcore\n");

	/*init ring pool*/
	initRing(ctx -> r, P_RING, 4096, -1);//name, ring_size, socket_id_any, 0
	//initRing(1, TCP_RING, 4096, -1);
	//initRing(2, UDP_RING, 4096, -1);

	/*init the timer*/
	//rte_timer_subsystem_init();

	return 0;
}

//end of dpdk init func

static void dpdk_daq_reset_stats(void *handle);

static int dpdk_daq_set_filter(void *handle, const char * filter);
/*in pcap not in pfring*/
static int translate_DPDK_FREAMS(int snaplen);

/*id is just in pfrings means device id*/
static int dpdk_daq_open(Dpdk_Context_t *context, int id);

static int update_hw_stats(Dpdk_Context_t *context);

/*following two func just in pfring not in pcap*/

static void dpdk_daq_sig_reload(int sig);

static void dpdk_daq_reload(Dpdk_Context_t * context);


/*init the modules*/
//init the daq func, but does not init the dpdk here.
static int dpdk_daq_initialize(const DAQ_Config_t * config, void **ctxt_ptr, char *errbuf, size_t len){
	
	if (config -> mode != DAQ_MODE_PASSIVE){
		snprintf(errbuf, len, "%s: Unsupported mode", __FUNCTION__);
		return DAQ_ERROR;
	}
	Dpdk_Context_t  ctx = calloc(1,sizeof(Dpdk_Context_t));
	if(!ctx){*
		snprintf(errbuf, len, "%s: failed to allocate memory for the new Endace DAG context!", __FUNCTION__);
		return DAQ_ERROR_NOMEM;
	}

	ctx -> state = DAQ_STATE_INITIALIZED;
	ctx -> snaplen = config -> snaplen; 
	ctx -> breakloop = 0;
	*ctxt_ptr = ctx;
	ctx -> start = 1;
	return DAQ_SUCCESS;
	
	
}
//here init the dpdk.
static int dpdk_daq_start(void *handle);{
	char argv[3][10] = {"temp","-c 2","-n 4"};
	(Dpdk_Context_t *)handle -> start = 1;
	initDPDK(handle,3,argv);
	return DAQ_SUCCESS;
}

static int dpdk_daq_acquire(
    void *handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user){
	int packets = 0;
	int i =0;
	DAQ_PktHdr_T hdr;
	struct ipv4_hdr * v4_hdr;
	DAQ_Verdict verdict;
	uint8_t * frame = NULL;
	uint8_t * cp = NULL;
	uint8_t *ep = NULL;

	uint64_t lts;
	dag_record_t *rec;
	size_t reclen;

	Dpdk_Context_t * ctx = (Dpdk_Context_t *)handle;
	if(!ctx)
		return DAQ_ERROR;
	ctx->analysis_func = callback;
	while(!ctx->breakloop && (packets < cnt || cnt <=0) && ctx ->start ){
		uint8_t port;
		for(port = 0;port < ctx->nb_ports;port++){
			struct rte_mbuf *bufs[BURST_SIZE];
			uint16_t nb_rx = rte_eth_rx_burst(port,0,bufs,BURST_SIZE);
			if(unlikely(nb_rx == 0))continue;
			else
				printf("Get %d packets.\n",nb_rx);
			for(i=0;i<nb_rx;i++){
				//constract hdr
				v4_hdr = mbufToIP(bufs[i]);
				hdr.caplen = v4_hdr->tot_len;
				gettimieofday(&hdr.tv);

				hdr.ingress_index = -1;
				hdr.ingress_group = -1;
				hdr.egress_index = -1;
				hdr.egress_index = -1;

				hdr.flags = 0;
				//callback
				ctx -> stats.packets_received ++;
				verdict = ctx ->analysis_func(user,&hdr,frame);
				if (verdict >= MAX_DAQ_VERDICT)
				{
					verdict = DAQ_VERDICT_PASS;
				}
				ctx->stats.verdicts[verdict]++;
				packets++;
				//end of callback
				packets ++;
			}
			//packets+=nb_rx;
			//if(packets >= cnt)
				//break;
			
		}
	}
	return DAQ_SUCCESS;
}

static int dpdk_daq_inject(void *handle, const DAQ_PktHdr_t *hdr, const uint8_t *packet_data, uint32_t len, int reverse){
		return DAQ_SUCCESS;
	}

static int dpdk_daq_breakloop(void *handle){	
	Dpdk_Context_t * ctx = (Dpdk_Context_t *)handle;
	if(!ctx)return DAQ_ERROR;
	ctx ->breakloop = 1;
	return DAQ_SUCCESS;
}

static int dpdk_daq_stop(void *handle){
	Dpdk_Context_t * ctx = (Dpdk_Context_t *)handle;
	if(!ctx)return DAQ_ERROR;
	ctx -> start = 0;
	ctx->breakloop = 1;
	return DAQ_SUCCESS;
}

static void dpdk_daq_shutdown(void *handle){
		Dpdk_Context_t * ctx = (Dpdk_Context_t *)handle;
	if(!ctx)return DAQ_ERROR;
	ctx -> start = 0;
	ctx -> breakloop = 1;
	free(ctx);
}

static DAQ_State dpdk_daq_check_status(void *handle)
{
	if(!handle)
		return DAQ_STATE_UNINITIALIZED;
	else 
		return ((Dpdk_Context_t *)handle) -> state;
}

static int dpdk_daq_get_stats(void *handle, DAQ_Stats_t *stats){
		Dpdk_Context_t * ctx = (Dpdk_Context_t *)handle;
	if(!ctx)return DAQ_ERROR;
	ctx->stats.hw_packets_received = (ctx->stats.packets_received + ctx->stats.hw_packets_dropped);
	memcpy(stats, &(ctx->stats), sizeof(DAQ_Stats_t));
	return DAQ_SUCCESS; 
	}

static void dpdk_daq_reset_stats(void *handle){
			Dpdk_Context_t * ctx = (Dpdk_Context_t *)handle;
		
			if(!ctx)return DAQ_ERROR;
			memset(&(ctx->stats), 0, sizeof(DAQ_Stats_t));
	}

static int dpdk_daq_get_snaplen(void *handle){
		Dpdk_Context_t * ctx = (Dpdk_Context_t *)handle;
	if (!ctx)
	{
		return 0;
	}
	return ctx->snaplen;
}

static uint32_t dpdk_daq_get_capabilities(void *handle){
    return DAQ_CAPA_NONE;
}

static int dpdk_daq_get_datalink_type(void *handle){
    return DLT_EN10MB;
}

static const char *dpdk_daq_get_errbuf(void *handle){
	Dpdk_Context_t * ctx = (Dpdk_Context_t *)handle;
	if (!ctx)
	{
		return NULL;
	}
	return ctx->errbuf;
}

static void dpdk_daq_set_errbuf(void *handle, const char *string){
	Dpdk_Context_t * ctx = (Dpdk_Context_t *)handle;
	if (!ctx)
	{
		return;
	}
	if (!string)
	{
		return;
	}
	DPE(ctx->errbuf, "%s", string);
}

static int dpdk_daq_get_device_index(void *handle, const char *device)
	{
		return DAQ_ERROR_NOTSUP;
	}


#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
const DAQ_Module_t dpdk_daq_module_data =
#endif
{
#ifndef WIN32
    .api_version = DAQ_API_VERSION,
    .module_version = DAQ_DPDK_VERSION,
    .name = "dpdk",
    .type = DAQ_TYPE_FILE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    .initialize = dpdk_daq_initialize,
    .set_filter = dpdk_daq_set_filter,
    .start = dpdk_daq_start,
    .acquire = dpdk_daq_acquire,
    .inject = dpdk_daq_inject,
    .breakloop = dpdk_daq_breakloop,
    .stop = dpdk_daq_stop,
    .shutdown = dpdk_daq_shutdown,
    .check_status = dpdk_daq_check_status,
    .get_stats = dpdk_daq_get_stats,
    .reset_stats = dpdk_daq_reset_stats,
    .get_snaplen = dpdk_daq_get_snaplen,
    .get_capabilities = dpdk_daq_get_capabilities,
    .get_datalink_type = dpdk_daq_get_datalink_type,
    .get_errbuf = dpdk_daq_get_errbuf,
    .set_errbuf = dpdk_daq_set_errbuf,
    .get_device_index = dpdk_daq_get_device_index,
    .modify_flow = NULL,
    .hup_prep = NULL,
    .hup_apply = NULL,
    .hup_post = NULL,
#else
    DAQ_API_VERSION,
    DAQ_DPDK_VERSION,
    "dpdk",
    DAQ_TYPE_FILE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    dpdk_daq_initialize,
    dpdk_daq_set_filter,
    dpdk_daq_start,
    dpdk_daq_acquire,
    dpdk_daq_inject,
    dpdk_daq_breakloop,
    dpdk_daq_stop,
    dpdk_daq_shutdown,
    dpdk_daq_check_status,
    dpdk_daq_get_stats,
    dpdk_daq_reset_stats,
    dpdk_daq_get_snaplen,
    dpdk_daq_get_capabilities,
    dpdk_daq_get_datalink_type,
    dpdk_daq_get_errbuf,
    dpdk_daq_set_errbuf,
    dpdk_daq_get_device_index,
    NULL,
    NULL,
    NULL,
    NULL,
#endif
};
