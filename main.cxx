#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <pcap.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>    /* Must precede if*.h */
#include <zlib.h>
#include <assert.h>

// EAPOL encapsulation: http://www.vocal.com/secure-communication/eapol-extensible-authentication-protocol-over-lan/
// EAP: http://tools.ietf.org/html/rfc3748


#define ETH_ALEN        6       /* Octets in one ethernet addr   */
#define ETH_HLEN        14      /* Total octets in header.   */
#define ETH_ZLEN        60      /* Min. octets in frame sans FCS */
#define ETH_DATA_LEN    1500        /* Max. octets in payload    */
#define ETH_FRAME_LEN   1514        /* Max. octets in frame sans FCS */

#define ETH_P_EAP       0x888e

unsigned char mac_nearest[ETH_ALEN]  = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x03 };

// eth0 address (to gateway)
unsigned char mac_external[ETH_ALEN] = { 0x20, 0x25, 0x64, 0x0B, 0xCF, 0x71 };

// eth2 address (to aterm)
unsigned char mac_internal[ETH_ALEN] = { 0x00, 0x25, 0x4B, 0xFC, 0xAC, 0x2E };

// eth address of aterm
unsigned char mac_aterm[ETH_ALEN]    = { 0x10, 0x66, 0x82, 0x23, 0xB3, 0x29 };

struct ethhdr {
    unsigned char   h_dest[ETH_ALEN];   /* destination eth addr */
    unsigned char   h_source[ETH_ALEN]; /* source ether addr    */
    unsigned short  h_proto;        /* packet type ID field */
} __attribute__((packed));

struct ethframe
{
    ethhdr  hdr;
    u_char  payload[ETH_DATA_LEN];
};

struct CaptureThread
{
    const char * devname;
    pthread_t thread;
    pcap_t * handle;

    CaptureThread(const char * name)
    {
        this->devname = name;
        this->thread = NULL;
        this->handle = NULL;
    }

    void start()
    {
        pthread_create(&thread, NULL, CaptureThread::_thread_entry, (void *)this);
    }

    void join()
    {
        void *arg;

        pthread_join(thread, &arg);
    }

    static void * _thread_entry(void *arg)
    {
        CaptureThread * me = (CaptureThread *)arg;

        return me->thread_entry();
    }

    void * thread_entry();
};

FILE * logfile = stderr;

const char * internal_devname = "eth2";
const char * external_devname = "eth0";

CaptureThread internal(internal_devname);
CaptureThread external(external_devname);


void print_ethernet_header(const u_char *Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
     
    fprintf(logfile , "Ethernet Header\n");
    fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(logfile , "   |-Protocol            : 0x%04x \n",(unsigned short)ntohs(eth->h_proto));

    int lc = 0;

    char buf[16];

    for(int i = 0; i < Size; i++)
    {
        if(lc == 0)
            fprintf(logfile, "    0x%08x: ", i);

        fprintf(logfile, "%02x", Buffer[i]);
        buf[lc] = Buffer[i];
        lc += 1;

        if(lc == 16)
        {
            fprintf(logfile, "    ");
            for(int j=0; j<lc; j++)
                fprintf(logfile, "%c", buf[j] > 32 ? buf[j] : '.');

            fprintf(logfile, "\n");
            lc = 0;
        }
        else
        {
            fprintf(logfile, " ");
        }
    }

    for(int j=0; j<lc; j++)
        fprintf(logfile, "%c", buf[j] > 32 ? buf[j] : '.');
    fprintf(logfile, "\n");
}

const char * eapcodestr(int code)
{
    switch(code)
    {
        case 1: return "REQUEST";
        case 2: return "RESPONSE";
        case 3: return "SUCCESS";
        case 4: return "FAILURE";
    }

    return "UNKNOWN";
}

const char * eaptypestr(int type)
{
    switch(type)
    {
        case 1: return "IDENTITY";
        case 2: return "NOTIFICATION";
        case 3: return "NAK";
        case 4: return "MD5-CHALLENGE";
    }

    return "";
}

void print_eapol(const u_char *Buffer, int Size)
{
    Buffer += sizeof(ethhdr);

    u_char  encver  = Buffer[0];
    u_char  enctype = Buffer[1];
    u_short enclen  = (Buffer[2] << 8) | Buffer[3];

    u_char  code  = Buffer[4];
    u_char  id    = Buffer[5];
    u_short len   = (Buffer[6] << 8) | Buffer[7];
    u_char  type  = Buffer[8];

    fprintf(logfile, "   EncVer:%d\n", encver);
    fprintf(logfile, "  EncType:%d\n", enctype);
    fprintf(logfile, "   EncLen:%d\n", enclen);
    fprintf(logfile, "     Code:%d (%s)\n", code, eapcodestr(code));
    fprintf(logfile, "       Id:%d\n", id);
    fprintf(logfile, "      Len:%d\n", len);
    fprintf(logfile, "     Type:%d (%s)\n", type, eaptypestr(type));
}

void print_packet(const u_char *Buffer, int Size)
{
    print_ethernet_header(Buffer, Size);

    print_eapol(Buffer, Size);
}


void internal_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethhdr *eth = (struct ethhdr *)packet;

    if(ntohs(eth->h_proto) != ETH_P_EAP)
        return;

    fprintf(logfile, "------------------------------------------------------------------------------------------------------------\n");
    fprintf(logfile, "Received %d bytes from internal interface\n", header->len);

    print_packet(packet, header->len);

    // dest address should always be the pseudo 'nearest' looking thing.
    //assert( memcmp(&eth->h_dest, mac_nearest, ETH_ALEN) == 0 );
    //assert( memcmp(&eth->h_source, mac_internal, ETH_ALEN) == 0 );

    // send packet out on the other interface
    //memcpy(eth->h_source, mac_external, ETH_ALEN);
    //print_packet(packet, header->len);

    int r = pcap_inject(external.handle, packet, header->len);

    fprintf(logfile, "Forwarded %d bytes to external interface\n", r);
    fprintf(logfile, "\n");
}


void external_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethhdr *eth = (struct ethhdr *)packet;

    if(ntohs(eth->h_proto) != ETH_P_EAP)
        return;

    fprintf(logfile, "------------------------------------------------------------------------------------------------------------\n");
    fprintf(logfile, "Received %d bytes from external interface\n", header->len);

    print_packet(packet, header->len);

    //assert( memcmp(&eth->h_dest, mac_external, ETH_ALEN) == 0 );

    // send packet out on the other interface
    //memcpy(eth->h_dest, mac_aterm, ETH_ALEN);
    //print_packet(packet, header->len);

    int r = pcap_inject(internal.handle, packet, header->len);

    fprintf(logfile, "Forwarded %d bytes to internal interface\n", r);
    fprintf(logfile, "\n");
}


void * CaptureThread::thread_entry()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char * eap_filter = "ether proto 0x888e";
    struct bpf_program eap_program;

    handle = pcap_open_live(devname, BUFSIZ, true, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", devname, errbuf);
        exit(2);
    }

    if (pcap_compile(handle, &eap_program, eap_filter, 1, 0) == -1)
    {
        pcap_geterr(handle);
        fprintf(stderr, "Couldn't parse filter '%s': %s\n", eap_filter, errbuf);
        exit(2);
    }

    if (pcap_setfilter(handle, &eap_program) == -1)
    {
        pcap_geterr(handle);
        fprintf(stderr, "Couldn't install filter '%s': %s\n", eap_filter, errbuf);
        exit(2);
    }

    if(!strcmp(devname, internal_devname))
        pcap_loop(handle, -1, internal_callback, NULL);
    else
        pcap_loop(handle, -1, external_callback, NULL);

    /* And close the session */
    pcap_close(handle);

    return NULL;
}

int docrc(u_char * buf, int size)
{
    uLong crc = crc32(0, NULL, 0);

    crc = crc32(crc, buf, size);

    buf[size+0] = crc & 0xff;
    buf[size+1] = (crc >> 8) & 0xff;
    buf[size+2] = (crc >> 16) & 0xff;
    buf[size+3] = (crc >> 24) & 0xff;

    return size + 4;
}

void send_identity(pcap_t * pcap)
{
    ethframe f;

    memset(&f, 0, sizeof(f));

    f.hdr.h_source[0] = 0x00;
    f.hdr.h_source[1] = 0x25;
    f.hdr.h_source[2] = 0x4b;
    f.hdr.h_source[3] = 0xfc;
    f.hdr.h_source[4] = 0xac;
    f.hdr.h_source[5] = 0x2e; 

    f.hdr.h_dest[0] = 0x10;
    f.hdr.h_dest[1] = 0x66;
    f.hdr.h_dest[2] = 0x82;
    f.hdr.h_dest[3] = 0x23;
    f.hdr.h_dest[4] = 0xb3;
    f.hdr.h_dest[5] = 0x29;

    f.hdr.h_proto = htons(ETH_P_EAP);

    f.payload[0] = 0x01;    // eapol: version
    f.payload[1] = 0x00;    // eapol: packet type
    f.payload[2] = 0x00;    // eapol: length
    f.payload[3] = 0x05;    // eapol: length

int pktid = 5;

    f.payload[4] = 0x01;    // EAP: request
    f.payload[5] = pktid;   // EAP: id
    f.payload[6] = 0x00;    // EAP: length
    f.payload[7] = 0x05;    // EAP: length
    f.payload[8] = 0x01;    // EAP: MD5 challenge
    f.payload[9] = 0x00;    // EAP: MD5 size
    f.payload[10] = 0x00;    // EAP: MD5 size
    f.payload[11] = 0x00;    // EAP: MD5 size
    f.payload[12] = 0x00;    // EAP: MD5 size

    int n = sizeof(ethhdr) + 13;

    print_packet((u_char *)&f, n);

    int r = pcap_inject(pcap, &f, n);
    printf("sent %d bytes\n", r);
}


void send_challenge(pcap_t * pcap)
{
    ethframe f;

    memset(&f, 0, sizeof(f));

    f.hdr.h_source[0] = 0x00;
    f.hdr.h_source[1] = 0x25;
    f.hdr.h_source[2] = 0x4b;
    f.hdr.h_source[3] = 0xfc;
    f.hdr.h_source[4] = 0xac;
    f.hdr.h_source[5] = 0x2e; 

    f.hdr.h_dest[0] = 0x10;
    f.hdr.h_dest[1] = 0x66;
    f.hdr.h_dest[2] = 0x82;
    f.hdr.h_dest[3] = 0x23;
    f.hdr.h_dest[4] = 0xb3;
    f.hdr.h_dest[5] = 0x29;

    f.hdr.h_proto = htons(ETH_P_EAP);

    f.payload[0] = 0x01;    // eapol: version
    f.payload[1] = 0x00;    // eapol: packet type
    f.payload[2] = 0x00;    // eapol: length
    f.payload[3] = 0x16;    // eapol: length

int pktid = 5;

    f.payload[4] = 0x01;    // EAP: request
    f.payload[5] = pktid;   // EAP: id
    f.payload[6] = 0x00;    // EAP: length
    f.payload[7] = 0x16;    // EAP: length
    f.payload[8] = 0x04;    // EAP: MD5 challenge
    f.payload[9] = 0x10;    // EAP: MD5 size



    int n = sizeof(ethhdr) + 10 + 16;

    //n = docrc((u_char *)&f, n);

    print_packet((u_char *)&f, n);

    int r = pcap_inject(pcap, &f, n);
    printf("sent %d bytes\n", r);
}


int main(int argc, const char **argv)
{
    fprintf(logfile, "eapolproxy starting %s\n", __DATE__);

    fprintf(logfile, "starting %s\n", internal_devname);
    internal.start();
    while(internal.handle == NULL)
        usleep(100000);

    fprintf(logfile, "starting %s\n", external_devname);
    external.start();

    while(external.handle == NULL)
        usleep(100000);

    fprintf(logfile, "ready\n");

    //send_identity(internal.handle);
    //sleep(1);
    //send_challenge(internal.handle);
 
    internal.join();
    external.join();

    return 1;
}

