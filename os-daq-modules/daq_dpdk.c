
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <pthread.h>
#include <daq_api.h>
#include <sfbpf.h>
#include <sfbpf_dlt.h>
/*
 * DPDK HEADER
 */

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define QUEUE_SIZE 128
#define PORT_SIZE 128
#define CORE_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define MAX_ARGS 64

#define DAQ_DPDK_VERSION  16.04

/* Hi! I'm completely arbitrary! */
//#define dpdk_MAX_INTERFACES       32

/* FreeBSD 10.0 uses an old version of dpdk, so work around it accordingly. */
/*#if dpdk_API < 10
#define nm_ring_next(r, i)      dpdk_RING_NEXT(r, i)
#define nm_ring_empty(r)        ((r)->avail == 0)
#endif
*/

#define DEBUG 1
#if DEBUG 
#define DBG(var, ...) printf(var, __VA_ARGS__)
#else 
#define DBG(var, ...) //printf(var, __VA_ARGS__)
#endif

typedef struct _dpdk_instance
{
    struct _dpdk_instance *next;
    struct _dpdk_instance *peer;
    int fd;
#define NMINST_FWD_BLOCKED     0x1
#define NMINST_TX_BLOCKED      0x2
  //  uint32_t flags;
    int index;
    //NIC config
    //uint16_t ring_size;
    uint16_t queue_size;
    uint16_t port;//the port id of nic.
    int start;
    int end;
    int tx_num;
    //
    struct rte_mbuf *bufs[BURST_SIZE];
    struct rte_mempool * mp;
    volatile int break_loop;
    DAQ_Stats_t stats;
    struct sfbpf_program fcode;
    DAQ_State state;
    char *filter;
    char errbuf[256];
} DPDKInstance;

typedef struct _dpdk_context
{
    char *device;
    char *filter;
    int snaplen;
    int timeout;
    int debug;
    int threadNum;//the num of threads use this content. If num ==0, then free the dpdkc.
    pthread_t  *portMap;//portmap[port] = threadId;
    DPDKInstance *instances;
    DPDKInstance **insMap;
    struct rte_mempool * mp;
    uint32_t intf_count;//the num of interface.
    struct sfbpf_program fcode;
    volatile int break_loop;
    DAQ_Stats_t stats;
    DAQ_State state;
    
    char errbuf[256];
} DPDK_Context_t;
DPDK_Context_t * local_ctx = NULL;
static int isInit = -1;
pthread_mutex_t mutex;
//todo

#define FIND_IDX() do { \
        pthread_t tid = pthread_self(); \
        idx = -1; \
        for (uint8_t i =0;i<dpdkc->intf_count;i++ ){ \
            if(tid == dpdkc->portMap[i]){ \
                idx = i; \
                break; \
            } \
        } \
        DBG("%s(),%d:idx %d tid %d.\n",__FUNCTION__,__LINE__,idx,tid); \
} while(0) 

static int parse_args(char *inputstring, char **argv)
{
    char **ap;

    for (ap = argv; (*ap = strsep(&inputstring, " \t")) != NULL;)
    {
        if (**ap != '\0')
            if (++ap >= &argv[MAX_ARGS])
                break;
    }
    return ap - argv;
}

static void destroy_instance(DPDKInstance *instance)
{
    if (instance)
    {
        for (int i =instance->start;i<instance->end;i++)
            rte_pktmbuf_free(instance->bufs[i]);
        //here may need change.
        rte_eth_dev_stop(instance->port);
        free(instance);
    }
}

static int dpdk_close(DPDK_Context_t *dpdkc)
{
    DPDKInstance *instance;

    if (!dpdkc)
        return -1;
    int idx = -1;
    FIND_IDX();
    if (idx == -1){
        return 0;
    }
    dpdkc->portMap[idx] = -1;
    pthread_mutex_lock(&mutex);
    dpdkc->threadNum--;
    if(dpdkc->threadNum >0){
        pthread_mutex_unlock(&mutex);
        return 0;
    }
    /* Free all of the device instances. */
    while ((instance = dpdkc->instances) != NULL)
    {
        dpdkc->instances = instance->next;
        if (dpdkc->debug)
        {
            printf("dpdk instance %d (%d) tx %d pkts on TX while forwarding.\n",
                    instance->port, instance->index, instance->tx_num);
        }
        sfbpf_freecode(&instance->fcode);
        destroy_instance(instance);
    }

    sfbpf_freecode(&dpdkc->fcode);

    dpdkc->state = DAQ_STATE_STOPPED;
    pthread_mutex_unlock(&mutex);
    return 0;
}
//here to init a port.
static DPDKInstance *create_instance(const char *device, DPDKInstance *parent, char *errbuf, size_t errlen)
{
    DPDKInstance *instance;
    int port;
    static int index = 0;
    instance = calloc(1, sizeof(DPDKInstance));
    if (!instance)
    {
        snprintf(errbuf, errlen, "%s: Could not allocate a new instance structure.", __FUNCTION__);
        goto err;
    }

    /* Initialize the instance, including an arbitrary and unique device index. */
    //instance->mem = MAP_FAILED;
    instance->index = index;
    index++;


    if(strncmp(device, "dpdk", 4) != 0 || sscanf(device,"dpdk%d",&port)!=1){
        snprintf(errbuf, errlen, "%s: Could not open /dev/dpdk: %s (%d)",
                    __FUNCTION__, strerror(errno), errno);
        goto err;
    }
    /* Initialize the dpdk request object. */
    instance -> port = port;
    instance -> queue_size = 1;//the queue size need to change.
    return instance;
err:
    destroy_instance(instance);
    return NULL;
}

static int create_bridge(DPDK_Context_t *dpdkc, const int port1, const int port2)
{
    DPDKInstance *instance, *peer1, *peer2;

    peer1 = peer2 = NULL;
    for (instance = dpdkc->instances; instance; instance = instance->next)
    {
        if (port1 == instance->port)
            peer1 = instance;
        else if (port2 == instance->port)
            peer2 = instance;
    }

    if (!peer1 || !peer2)
        return DAQ_ERROR_NODEV;

    peer1->peer = peer2;
    peer2->peer = peer1;

    return DAQ_SUCCESS;
}
//start a port to get core.
static int start_instance(DPDK_Context_t *dpdkc, DPDKInstance *instance)
{
    DBG("%s():%d.\n",__FUNCTION__,__LINE__);
    /*
    int idx = -1;
    pthread_t tid = pthread_self();
    for (int i =0;i<dpdkc->intf_count;i++ ){
        if(tid == dpdkc->portMap[i]){
            idx = i;
            break;
        }
    }
    if (idx == -1){
        DPE(dpdkc->errbuf, "%s: Couldn't start device for thread %d\n", __FUNCTION__, tid);
        return DAQ_ERROR;
    }
    instance = insMap[i];*/
    struct rte_mempool * mp = dpdkc->mp;
    int queue = instance -> queue_size;
    //instance -> queue_size = 4;
    static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
	};
    int port = instance -> port;
    if(port > rte_eth_dev_count()){
        DBG("%s():%d.\n",__FUNCTION__,__LINE__);
        return DAQ_ERROR;
    }
    int retval = rte_eth_dev_configure(port,queue,queue,&port_conf);
    if(retval !=0){
        DPE(dpdkc->errbuf, "%s: Couldn't configure port %d\n", __FUNCTION__, port);
        return DAQ_ERROR;
    }
    for(queue = 0; queue < instance -> queue_size;queue++){
        retval = rte_eth_rx_queue_setup(port, queue, RX_RING_SIZE,rte_eth_dev_socket_id(port), NULL, mp);
		if (retval < 0){
            DPE(dpdkc->errbuf, "%s: Couldn't setup rx queue %d for port %d\n", __FUNCTION__, queue, port);
			return DAQ_ERROR;
        }
        retval = rte_eth_tx_queue_setup(port, queue, TX_RING_SIZE,rte_eth_dev_socket_id(port), NULL);
		if (retval < 0){
            DPE(dpdkc->errbuf, "%s: Couldn't setup tx queue %d for port %d\n", __FUNCTION__, queue, port);
			return	DAQ_ERROR;
        }
    }
    retval = rte_eth_dev_start(port);
    if(retval <0){
        DPE(dpdkc->errbuf, "%s: Couldn't start device for port %d\n", __FUNCTION__, port);
        return DAQ_ERROR;
    }
    //here need to edit.
    rte_eth_promiscuous_enable(port);
    instance -> start = 0;
    instance -> end = 0;
    instance ->tx_num = 0;
    instance ->mp = mp;
    return DAQ_SUCCESS;
}

static int dpdk_daq_initialize(const DAQ_Config_t * config, void **ctxt_ptr, char *errbuf, size_t errlen)
{
    DPDK_Context_t *dpdkc;

    DPDKInstance *instance;
    DAQ_Dict *entry;
    char intf[IFNAMSIZ];
    uint32_t num_intfs = 0;
    size_t len;
    int port1,port2,ports;
    char  *dev;
    static int count  =0;
    char *dpdk_args = NULL;
    char argv0[] = "NachtZ";
    char *argv[MAX_ARGS + 1];
    int rval = DAQ_ERROR,ret;
    if(isInit == -1){
        DBG("%s(),%d:Init mutex.\n",__FUNCTION__,__LINE__);
        pthread_mutex_init(&mutex,NULL);
        isInit = 0;
    }
    pthread_mutex_lock(&mutex);
    DBG("%s(),%d:Lock Mutex.\n",__FUNCTION__,__LINE__);
    if(isInit == 1){
        int idx = -1;
        dpdkc = local_ctx;
        for(int i =0;i<dpdkc->intf_count;i++){
            if (dpdkc->portMap[i] == -1){
                idx = i;
                break;
            }
        }
        if (idx == -1){
            snprintf(errbuf, errlen, "%s: Couldn't found free port!", __FUNCTION__);
            pthread_mutex_unlock(&mutex);
            return DAQ_ERROR_NODEV;
        }
        dpdkc->portMap[idx] = pthread_self();
        dpdkc->threadNum =1;
        *ctxt_ptr = local_ctx;
        
        pthread_mutex_unlock(&mutex);
        return DAQ_SUCCESS;
    }
    DBG("In NachtZ's edition dpdk module of daq:%d.\n",count ++);
    dpdkc = calloc(1, sizeof(DPDK_Context_t));
    if (!dpdkc)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the new DPDK context!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    dpdkc->device = strdup(config->name);
    if (!dpdkc->device)
    {
        snprintf(errbuf, errlen, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    dpdkc->snaplen = config->snaplen;
    dpdkc->timeout = (config->timeout > 0) ? (int) config->timeout : -1;
    //here need to be edit.
    /*int argc = 3;
    char * argv[] = {"dpdk","-c","3"};
    ret = rte_eal_init(argc,argv);
    if(ret <0){
        snprintf(errbuf, errlen, "%s: EAL init failed!", __FUNCTION__);
        rval = DAQ_ERROR_INVAL;
        goto err;
    }*/
    for (entry = config->values; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, "dpdk_args"))
            dpdk_args = entry->value;
    }

    if (!dpdk_args)
    {
        snprintf(errbuf, errlen, "%s: Missing EAL arguments!", __FUNCTION__);
        rval = DAQ_ERROR_INVAL;
        goto err;
    }
    argv[0] = argv0;
    int argc = parse_args(dpdk_args, &argv[1]) + 1;
    optind = 1;

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
    {
        snprintf(errbuf, errlen, "%s: Invalid EAL arguments!\n", __FUNCTION__);
        rval = DAQ_ERROR_INVAL;
        goto err;
    }  
    
    ports = rte_eth_dev_count();
    if(ports <0){
        snprintf(errbuf, errlen, "%s: No ports found!", __FUNCTION__);
        rval = DAQ_ERROR_NODEV;
        goto err;
    }
    dpdkc -> mp = rte_pktmbuf_pool_create("MBUF_POOL",
		NUM_MBUFS * ports, MBUF_CACHE_SIZE, 0,
		RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if(dpdkc ->mp == NULL){
        snprintf(errbuf, errlen, "%s: No Mem reserved", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }
    dev = dpdkc->device;
    if (*dev == ':' || ((len = strlen(dev)) > 0 && *(dev + len - 1) == ':') || 
            (config->mode == DAQ_MODE_PASSIVE && strstr(dev, "::")))
    {
        snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!", __FUNCTION__, dpdkc->device);
        goto err;
    }

    while (*dev != '\0')
    {
        len = strcspn(dev, ":");
        if (len >= sizeof(intf))
        {
            snprintf(errbuf, errlen, "%s: Interface name too long! (%zu)", __FUNCTION__, len);
            goto err;
        }
        if (len != 0)
        {
            dpdkc->intf_count++;
            if (dpdkc->intf_count > ports)
            {
                snprintf(errbuf, errlen, "%s: Using more than %d interfaces is not supported!",
                            __FUNCTION__, ports);
                goto err;
            }
            snprintf(intf, len + 1, "%s", dev);
            instance = create_instance(intf, dpdkc->instances, errbuf, errlen);
            if (!instance)
                goto err;

            instance->next = dpdkc->instances;
            dpdkc->instances = instance;
            num_intfs++;
            if (config->mode != DAQ_MODE_PASSIVE)
            {
                if (num_intfs == 2)
                {
                    //name1 = nmc->instances->next->req.nr_name;
                    //name2 = nmc->instances->req.nr_name;
                    port1 = dpdkc -> instances -> next ->port;
                    port2 = dpdkc -> instances -> port;

                    if (create_bridge(dpdkc, port1, port2) != DAQ_SUCCESS)
                    {
                        snprintf(errbuf, errlen, "%s: Couldn't create the bridge between %d and %d!",
                                    __FUNCTION__, port1, port2);
                        goto err;
                    }
                    num_intfs = 0;
                }
                else if (num_intfs > 2)
                    break;
            }
        }
        else
            len = 1;
        dev += len;
    }
    /* If there are any leftover unbridged interfaces and we're not in Passive mode, error out. */
    if (!dpdkc->instances || (config->mode != DAQ_MODE_PASSIVE && num_intfs != 0))
    {
        snprintf(errbuf, errlen, "%s: Invalid interface specification: '%s'!",
                    __FUNCTION__, dpdkc->device);
        goto err;
    }
    //to init the thread map and instances map,  then put this thread into the thread map.
    if(dpdkc->intf_count >0){
        dpdkc->insMap = calloc(1,dpdkc->intf_count * sizeof(DPDKInstance *));
        dpdkc->portMap = calloc(1,dpdkc->intf_count * sizeof(pthread_t));
        if(dpdkc->insMap == NULL || dpdkc->portMap == NULL){
        snprintf(errbuf, errlen, "%s: Can't calloc the insMap's mem!",
                    __FUNCTION__ );
        goto err;
        }
        instance = dpdkc->instances;
        for (int i =0;instance!= NULL&& i< dpdkc->intf_count;i++){
            dpdkc->insMap[i] = instance;
            instance->state = DAQ_STATE_INITIALIZED;
            instance = instance->next;
            dpdkc->portMap[i] = -1;
            DBG("%s() in %d: isnMap %d is %d.\n",__FUNCTION__,__LINE__,i,dpdkc->insMap[i]->port);
        }
        dpdkc->portMap[0] = pthread_self();//get the id;
        dpdkc->threadNum = 1;
    }
    
    
    /* Initialize other default configuration values. */
    dpdkc->debug = 0;

    /* Import the configuration dictionary requests. */
    for (entry = config->values; entry; entry = entry->next)
    {
        if (!strcmp(entry->key, "debug"))
            dpdkc->debug = 1;
    }

    dpdkc->state = DAQ_STATE_INITIALIZED;

    *ctxt_ptr = dpdkc;
    local_ctx = dpdkc;
    isInit = 1;
    DBG("%s() in %d:unluck, T.\n",__FUNCTION__,__LINE__);
    pthread_mutex_unlock(&mutex);
    return DAQ_SUCCESS;

err:
    DBG("%s() in %d:Error :%s.\n",__FUNCTION__,__LINE__,errbuf);
    if (dpdkc)
    {
        dpdk_close(dpdkc);
        if (dpdkc->device)
            free(dpdkc->device);
        free(dpdkc);
    }
    DBG("%s() in %d:unluck, F.\n",__FUNCTION__,__LINE__);
    pthread_mutex_unlock(&mutex);
    return rval;
}

static int dpdk_daq_set_filter(void *handle, const char *filter)
{
    DPDK_Context_t *dpdkc = (DPDK_Context_t *) handle;
    struct sfbpf_program fcode;
    int idx = -1;
    FIND_IDX();
    if(idx == -1){
        DPE(dpdkc->errbuf, "%s: Couldn't find the port!", __FUNCTION__);
        return DAQ_ERROR;
    }
    if (dpdkc->insMap[idx]->filter)
        free(dpdkc->insMap[idx]->filter);

    dpdkc->insMap[idx]->filter = strdup(filter);
    if (!dpdkc->insMap[idx]->filter)
    {
        DPE(dpdkc->insMap[idx]->errbuf, "%s: Couldn't allocate memory for the filter string!", __FUNCTION__);
        return DAQ_ERROR;
    }

    if (sfbpf_compile(dpdkc->snaplen, DLT_EN10MB, &fcode, dpdkc->insMap[idx]->filter, 1, 0) < 0)
    {
        DPE(dpdkc->insMap[idx]->errbuf, "%s: BPF state machine compilation failed!", __FUNCTION__);
        return DAQ_ERROR;
    }

    sfbpf_freecode(&dpdkc->insMap[idx]->filter);
    dpdkc->insMap[idx]->fcode.bf_len = fcode.bf_len;
    dpdkc->insMap[idx]->fcode.bf_insns = fcode.bf_insns;

    return DAQ_SUCCESS;
}

static int dpdk_daq_start(void *handle)
{
    DBG("%s() in line %d.\n",__FUNCTION__,__LINE__);
    DPDK_Context_t *dpdkc = (DPDK_Context_t *) handle;
    DPDKInstance *instance;
    int idx = -1;
    FIND_IDX();
    if(idx == -1){
        DBG("%s() in line %d: 404.\n",__FUNCTION__,__LINE__);
        return DAQ_ERROR;
    }
    instance = dpdkc->insMap[idx];
    if (start_instance(dpdkc, instance) != DAQ_SUCCESS)
            return DAQ_ERROR;
//todo: change the dpdkc->state to instance->state
    memset(&instance->stats, 0, sizeof(DAQ_Stats_t));;

    instance->state = DAQ_STATE_STARTED;

    return DAQ_SUCCESS;
}

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_IGNORE */
    DAQ_VERDICT_BLOCK       /* DAQ_VERDICT_RETRY */
};

static int dpdk_daq_acquire(void *handle, int cnt, DAQ_Analysis_Func_t callback, DAQ_Meta_Func_t metaback, void *user)
{
    //struct pollfd pfd[dpdk_MAX_INTERFACES];
    //struct dpdk_ring *rx_ring, *tx_ring;
    //struct dpdk_slot *rx_slot, *tx_slot;
    DPDK_Context_t *dpdkc = (DPDK_Context_t *) handle;
    int idx = -1;
    FIND_IDX();
    if (idx == -1){
        return 0;
    }
    
    DPDKInstance *instance = dpdkc->insMap[idx], *peer;
    DAQ_PktHdr_t daqhdr;
    DAQ_Verdict verdict;
    const uint8_t *data;
    uint32_t i, rx_cur;
    uint16_t len;
    int got_one, ignored_one,sent_one;
    int ret, c = 0,queue;
    int burst_size;
    struct timeval ts;
    struct rte_mbuf *bufs[BURST_SIZE];
    while (c < cnt || cnt <= 0)
    {
        got_one = 0;
        ignored_one = 0;
      //      start_rx_ring = instance->cur_rx_ring;

                /* Has breakloop() been called? */
            if (instance->break_loop)
            {
                instance->break_loop = 0;
                return 0;
            }
            peer = instance -> peer;
            if(peer){
                burst_size = peer->end - peer->start;
                if(burst_size >0)
                    goto poll;
            }

            verdict = DAQ_VERDICT_PASS;

                /* If we blocked on forwarding previously, it means we know we
                    already want to send this packet, so attempt to do so
                    immediately. */
                    /*
                if (instance->flags & NMINST_FWD_BLOCKED)
                {
                    instance->flags &= ~NMINST_FWD_BLOCKED;
                    got_one = 1;
                    goto send_packet;
                }

                nmc->stats.hw_packets_received++;

                if (nmc->fcode.bf_insns && sfbpf_filter(nmc->fcode.bf_insns, data, len, len) == 0)
                {
                    ignored_one = 1;
                    nmc->stats.packets_filtered++;
                    goto send_packet;
                }*/
            for(queue = 0;queue < instance -> queue_size;queue ++){
                gettimeofday(&ts,NULL);
                if(cnt <=0 || BURST_SIZE + c <= cnt){
                    burst_size = BURST_SIZE;
                }else{
                    burst_size =  cnt - c;
                }
                uint16_t nb_rx = rte_eth_rx_burst(instance->port,queue,bufs,burst_size);
                for(i =0;i<nb_rx;++i){
                    verdict = DAQ_VERDICT_PASS;
                    data = rte_pktmbuf_mtod(bufs[i],void *);
                    len = rte_pktmbuf_data_len(bufs[i]);
                    instance->stats.hw_packets_received ++;
                    if (instance->fcode.bf_insns && sfbpf_filter(instance->fcode.bf_insns, data, len, len) == 0)
                    {
                        ignored_one = 1;
                        instance->stats.packets_filtered++;
                        goto send_packet;
                    }
                    got_one = 1;
                    daqhdr.ts = ts;
                    daqhdr.caplen = len;
                    daqhdr.pktlen = len;
                    daqhdr.ingress_index = instance->index;
                    daqhdr.egress_index = peer ? peer->index : DAQ_PKTHDR_UNKNOWN;
                    daqhdr.ingress_group = DAQ_PKTHDR_UNKNOWN;
                    daqhdr.egress_group = DAQ_PKTHDR_UNKNOWN;
                    daqhdr.flags = 0;
                    daqhdr.opaque = 0;
                    daqhdr.priv_ptr = NULL;
                    daqhdr.address_space_id = 0;

                    if (callback)
                    {
                        verdict = callback(user, &daqhdr, data);
                        if (verdict >= MAX_DAQ_VERDICT)
                            verdict = DAQ_VERDICT_PASS;
                        instance->stats.verdicts[verdict]++;
                        verdict = verdict_translation_table[verdict];
                    }
                    instance->stats.packets_received++;
                    c++;
send_packet:
                    if (verdict == DAQ_VERDICT_PASS && instance->peer)
                    {
                        peer->bufs[peer->end] =bufs[i];
                        peer->end ++;
                    }else{
                        rte_pktmbuf_free(bufs[i]);
                    }
                }
            }

            if (peer){
                burst_size = peer->end - peer->start;
                if (unlikely(burst_size == 0))
                    continue;
            
poll:
                for (queue = 0;burst_size !=0 && queue < peer->queue_size;queue ++){
                    const uint16_t nb_tx = rte_eth_tx_burst(peer->port,queue,&peer->bufs[peer->start],burst_size);
                    if (unlikely(nb_tx ==0))
                        continue;
                    sent_one = 1;
                    burst_size -= nb_tx;
                    peer->start += nb_tx;
                }
                if (burst_size == 0){
                    peer->start = 0;
                    peer->end = 0;
                }
            }
        
        if (!got_one && !ignored_one && !sent_one)
        {
            struct timeval now;
            if(dpdkc->timeout == -1)
                continue;
            gettimeofday(&now,NULL);
            if (now.tv_sec > ts.tv_sec ||(now.tv_usec - ts.tv_usec) > dpdkc->timeout * 1000)
                return 0;
            else{
                gettimeofday(&ts,NULL);
            }
        }
    }

    return 0;
}

static int dpdk_daq_inject(void *handle, const DAQ_PktHdr_t *hdr,
                             const uint8_t *packet_data, uint32_t len,
                             int reverse)
{
    //this function do not edit. As it look for instance according to it's own mark.
    DPDK_Context_t *dpdkc = (DPDK_Context_t *) handle;
    DPDKInstance *instance;
    struct rte_mbuf * m = NULL;

    /* Find the instance that the packet was received on. */
    for (instance = dpdkc->instances; instance; instance = instance->next)
    {
        if (instance->index == hdr->ingress_index)
            break;
    }

    if (!instance)
    {
        DPE(dpdkc->errbuf, "%s: Unrecognized ingress interface specified: %u",
                __FUNCTION__, hdr->ingress_index);
        return DAQ_ERROR_NODEV;
    }

    if (!reverse && !(instance = instance->peer))
    {
        DPE(dpdkc->errbuf, "%s: Specified ingress interface (%u) has no peer for forward injection.",
                __FUNCTION__, hdr->ingress_index);
        return DAQ_ERROR_NODEV;
    }

    /* Find a TX ring with space to send on. */
    m = rte_pktmbuf_alloc(instance->mp);
    if(m == NULL){
        DPE(dpdkc->errbuf, "%s: Specified ingress interface (%u) has no mem reserved.",
                __FUNCTION__, hdr->ingress_index);
        return DAQ_ERROR_NOMEM;
    }
    rte_memcpy(rte_pktmbuf_mtod(m,void *),packet_data,len);
    //here may have bugs.
    if(0 == rte_eth_tx_burst(instance->port,instance->tx_num &3,&m,1)){
        DPE(dpdkc->errbuf, "%s: Could not Send.  Try again.", __FUNCTION__);
        return DAQ_ERROR_AGAIN;
    }
    instance->tx_num ++;
    return DAQ_SUCCESS;
    /* If we got here, it means we couldn't find an available TX slot, so tell the user to try again. */

}

static int dpdk_daq_breakloop(void *handle)
{
    DPDK_Context_t *dpdkc = (DPDK_Context_t *) handle;

    int idx = -1;
    FIND_IDX();
    if (idx == -1){
        for (int i =0;i< dpdkc->intf_count;i++){
            dpdkc->insMap[i]->break_loop = 1;
        }
        return DAQ_SUCCESS;
    }
    dpdkc->insMap[idx]->break_loop = 1;

    return DAQ_SUCCESS;
}

static int dpdk_daq_stop(void *handle)
{
    DPDK_Context_t *dpdkc = (DPDK_Context_t *) handle;

    dpdk_close(dpdkc);

    return DAQ_SUCCESS;
}

static void dpdk_daq_shutdown(void *handle)
{
    DPDK_Context_t *dpdkc = (DPDK_Context_t *) handle;

    dpdk_close(dpdkc);
    if(dpdkc->threadNum != 0){
        return ;
    }
    if (dpdkc->device)
        free(dpdkc->device);
    if (dpdkc->filter)
        free(dpdkc->filter);
    free(dpdkc);
    isInit = 0;
}

static DAQ_State dpdk_daq_check_status(void *handle)
{
    DPDK_Context_t *dpdkc = (DPDK_Context_t *) handle;
    int idx = -1;
    FIND_IDX();
	return dpdkc->insMap[idx]->state;
}

static int dpdk_daq_get_stats(void *handle, DAQ_Stats_t * stats)
{
    DPDK_Context_t *dpdkc = (DPDK_Context_t *) handle;
    int idx = -1;
    FIND_IDX();
    memcpy(stats, &dpdkc->insMap[idx]->stats, sizeof(DAQ_Stats_t));

    return DAQ_SUCCESS;
}

static void dpdk_daq_reset_stats(void *handle)
{
    DPDK_Context_t *dpdkc = (DPDK_Context_t *) handle;
    int idx = -1;
    FIND_IDX();
    memset(&dpdkc->insMap[idx]->stats, 0, sizeof(DAQ_Stats_t));;
}

static int dpdk_daq_get_snaplen(void *handle)
{
    DPDK_Context_t *dpdkc = (DPDK_Context_t *) handle;

    return dpdkc->snaplen;
}

static uint32_t dpdk_daq_get_capabilities(void *handle)
{
    return DAQ_CAPA_BLOCK | DAQ_CAPA_REPLACE | DAQ_CAPA_INJECT |
            DAQ_CAPA_UNPRIV_START | DAQ_CAPA_BREAKLOOP | DAQ_CAPA_BPF |
            DAQ_CAPA_DEVICE_INDEX;
}

static int dpdk_daq_get_datalink_type(void *handle)
{
    return DLT_EN10MB;
}

static const char *dpdk_daq_get_errbuf(void *handle)
{
    DPDK_Context_t *dpdkc = (DPDK_Context_t *) handle;
    int idx = -1;
    FIND_IDX();
    return dpdkc->insMap[idx]->errbuf;
}

static void dpdk_daq_set_errbuf(void *handle, const char *string)
{
    DPDK_Context_t *dpdkc = (DPDK_Context_t *) handle;

    if (!string)
        return;
    int idx = -1;
    FIND_IDX();
    DPE(dpdkc->insMap[idx]->errbuf, "%s", string);
}

static int dpdk_daq_get_device_index(void *handle, const char *device)
{
    DPDK_Context_t *dpdkc = (DPDK_Context_t *) handle;
    DPDKInstance *instance;
    int port;
    if(sscanf(device,"dpdk%d",&port)!=1){
        return DAQ_ERROR_NODEV;
    }

    for (instance = dpdkc->instances; instance; instance = instance->next)
    {
        if (port == instance->port)
            return instance->index;
    }

    return DAQ_ERROR_NODEV;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_Module_t DAQ_MODULE_DATA =
#else
const DAQ_Module_t dpdk_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_API_VERSION,
    /* .module_version = */ DAQ_DPDK_VERSION,
    /* .name = */ "dpdk",
    /* .type = */ DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .initialize = */ dpdk_daq_initialize,
    /* .set_filter = */ dpdk_daq_set_filter,
    /* .start = */ dpdk_daq_start,
    /* .acquire = */ dpdk_daq_acquire,
    /* .inject = */ dpdk_daq_inject,
    /* .breakloop = */ dpdk_daq_breakloop,
    /* .stop = */ dpdk_daq_stop,
    /* .shutdown = */ dpdk_daq_shutdown,
    /* .check_status = */ dpdk_daq_check_status,
    /* .get_stats = */ dpdk_daq_get_stats,
    /* .reset_stats = */ dpdk_daq_reset_stats,
    /* .get_snaplen = */ dpdk_daq_get_snaplen,
    /* .get_capabilities = */ dpdk_daq_get_capabilities,
    /* .get_datalink_type = */ dpdk_daq_get_datalink_type,
    /* .get_errbuf = */ dpdk_daq_get_errbuf,
    /* .set_errbuf = */ dpdk_daq_set_errbuf,
    /* .get_device_index = */ dpdk_daq_get_device_index,
    /* .modify_flow = */ NULL,
    /* .hup_prep = */ NULL,
    /* .hup_apply = */ NULL,
    /* .hup_post = */ NULL,
    /* .dp_add_dc = */ NULL
};
