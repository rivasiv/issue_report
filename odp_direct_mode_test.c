//gcc odp_direct_mode_test.c -g -O0 -lodp-dpdk -lodphelper $(pkg-config --libs libdpdk) -o odmt

#include <stdio.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>

#include <rte_errno.h>

#include <odp_api.h>

#define SHM_PKT_POOL_BUF_SIZE  1856
#define SHM_PKT_POOL_SIZE      4 * 4 * 4 * (512*2048)
#define NVME_MAX_BDEVS_PER_RPC 128
#define MAX_PACKET_SIZE 1600

#define NSEC_PER_SEC 1000000000L

//odp stuff -----
odp_instance_t          odp_instance;
odp_pool_param_t        params;
odp_pool_t              pool;
odp_pktio_param_t       pktio_param;
odp_pktio_t             pktio;
odp_pktin_queue_param_t pktin_param;

odp_pktin_queue_t inq_direct;    // DIRECT PKTIO queue 


odp_init_t init_param;

void hexdump(void*, unsigned int );

void hexdump(void *addr, unsigned int size)
{
        unsigned int i;
        /* move with 1 byte step */
        unsigned char *p = (unsigned char*)addr;

        //printf("addr : %p \n", addr);

        if (!size)
        {
                printf("bad size %u\n",size);
                return;
        }

        for (i = 0; i < size; i++)
        {
                if (!(i % 16))    /* 16 bytes on line */
                {
                        if (i)
                                printf("\n");
                        printf("0x%lX | ", (long unsigned int)(p+i)); /* print addr at the line begin */
                }
                printf("%02X ", p[i]); /* space here */
        }

        printf("\n");
}

int main(int argc, char *argv[])
{
	int rv = 0;
	char devname[] = "0";	
	odp_pktio_info_t info;
	odp_pktio_config_t pktio_config;
	odp_pktio_capability_t pktio_cpb;
	int pkts = 0;

	//odp
	odp_packet_t pkt_tbl[32];
	odp_time_t time;
	int pkt_len;

	/*GENERAL INIT*/
	odp_init_param_init(&init_param);

	//rv = odp_init_global(&odp_instance, NULL, NULL);
	rv = odp_init_global(&odp_instance, &init_param, NULL);
	if (rv) {
		printf("Error! ODP global init failed.");
		exit(1);
	}

	rv = odp_init_local(odp_instance, ODP_THREAD_CONTROL);
	if (rv) {
		printf("Error! ODP local init failed.");
		exit(1);
	}
	
	/*POOL INIT*/
	odp_pool_param_init(&params);
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_SIZE/SHM_PKT_POOL_BUF_SIZE;
	params.type        = ODP_POOL_PACKET;
	pool = odp_pool_create("packet_pool", &params);
	if (pool == ODP_POOL_INVALID) exit(1);

	odp_pktio_param_init(&pktio_param);

	odp_sys_info_print();

	/* ODP_PKTIN_MODE_QUEUE || ODP_PKTIN_MODE_DIRECT*/
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;


	printf("setting queue mode\n");
	pktio = odp_pktio_open(devname, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID){
		printf("Error! Failed to open pktio!\n");
		exit(1);
	}

	odp_pktio_config_init(&pktio_config);

	pktio_config.pktin.bit.ts_all = 1;

	pktio_config.parser.layer = ODP_PROTO_LAYER_ALL;

	odp_pktio_config(pktio, &pktio_config);

	if (odp_pktio_info(pktio, &info)) {
		printf("Error! pktio info failed\n");
		return -1;
	}

	odp_pktio_promisc_mode_set(pktio, 1);

	rv = odp_pktio_capability(pktio, &pktio_cpb);
	if (rv) {
		printf("Error! pktio %s: unable to read capabilities!\n", info.drv_name);
		exit(1);
	}
	
	printf("ODP: created pktio %" PRIu64 ", drv: %s, max supported queues on intf %u\n", odp_pktio_to_u64(pktio), info.drv_name, pktio_cpb.max_input_queues);
			
	odp_pktin_queue_param_init(&pktin_param);

		pktin_param.op_mode     = ODP_PKTIO_OP_MT_UNSAFE;

pktin_param.hash_enable = 1;
pktin_param.hash_proto.proto.ipv4_udp = 1;
pktin_param.hash_proto.proto.ipv4_tcp = 1;
pktin_param.hash_proto.proto.ipv4 = 1;
pktin_param.hash_proto.proto.ipv6_udp = 1;
pktin_param.hash_proto.proto.ipv6_tcp = 1;
pktin_param.hash_proto.proto.ipv6 = 1;

	pktin_param.num_queues  = 1;
	
	odp_pktin_queue_config(pktio, &pktin_param);
	odp_pktout_queue_config(pktio, NULL);

	rv = odp_pktio_start(pktio);
	if (rv) {
		printf("\nError! thread creation failed. Exiting\n");
		exit(1);
	}

	if ((rv = odp_pktin_queue(pktio, &inq_direct, 1)) != 1) {
		printf("Error! pktin queue query failed \n");
		exit(1);
	}

	//odp thread init
	rv = odp_init_local(odp_instance, ODP_THREAD_WORKER);

	while(1)
	{
		pkts = odp_pktin_recv(inq_direct, pkt_tbl, 32);
		if (pkts <= 0) {
			continue;
		}

		for (int i = 0; i < pkts; i++) {

			odp_packet_t pkt = pkt_tbl[i];

			pkt_len = (int)odp_packet_len(pkt);

			hexdump(odp_packet_l2_ptr(pkt, NULL), pkt_len);

		} // pkt table processing

		printf("Freeing....number of packets %i\n",pkts);
		odp_packet_free_multi(pkt_tbl, pkts);
		printf("Free'ed....\n");
	} // main loop

	return rv;
}
