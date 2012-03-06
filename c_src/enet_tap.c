#include <stdlib.h>
#include <event.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <err.h>

#ifdef __linux__
#include <net/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <sys/ioctl.h>
#include <errno.h>
#endif

#define MAX_PACKET_SIZE 1500

#define PORT_PROTO_RUNNING 0
#define PORT_PROTO_PACKET 1

/*

Protocol:
 From Erlang (stdin)
 From Erlang: <<PktSize:16/big, EthernetFrame:(PktSize - 2)/binary>>*

 To Erlang (stdout)
 To Erlang: ( <<PktSize:16/big, PORT_PROTO_RUNNING>> |
              <<PktSize:16/big, PORT_PROTO_PACKET,
                EthernetFrame:(PktSize - 3)/binary>> )*

*/

int debug = 0;

struct bufferevent *to_erlang;
struct bufferevent *from_erlang;

int tap_fd;
struct event tap;

struct event_base* eb;

typedef struct _enet_buf {
    u_char *buf;
    u_int16_t len;
} enet_buf;

void erl_input(struct bufferevent *ev, void *ud) {
    u_int16_t len;
    size_t data_read;
    size_t data_written;
    enet_buf *ep = ud;

    // Read 2 byte data length (unsigned, bigendian)
    if (bufferevent_read(from_erlang, &len, sizeof(len)) != sizeof(len)) {
        errx(2, "Couldn't allocate 2 bytes for len?!?");
    }
    len = ntohs(len);
    //fprintf(stderr, "Len bytes: %d.\n", len);

    // Writing a frame that exceeds our MTU will result in an error
    // (and overflow our buf)
    if (len > ep->len) {
        errx(2, "Frame length (%u) is larger than the tap MTU (%u)", len, ep->len);
    }

    data_read = bufferevent_read(from_erlang, ep->buf, len);
    if (data_read != len) {
        errx(2, "Wanted to read %u bytes data but got %zu instead", len, data_read);
    }

    //fprintf(stderr, "Writing %zu bytes from erlang to tap.\n", data_read);
    //bufferevent_write(to_erlang, size_buf, 2);
    //bufferevent_write(to_erlang, data_buf, data_read);
    data_written = write(tap_fd, ep->buf, data_read);
    if (data_written == -1) {
        err(2, "write");
    }
    if (data_written != data_read) {
        fprintf(stderr, "Tried to write %zu bytes to the tap, but got %zu instead\n", data_read, data_written);
    }
}

void send_to_erlang(u_char *buffer, size_t buffer_len) {
    u_int16_t erl_pkt_len;
    u_char size_buf[3];

    size_buf[2] = PORT_PROTO_PACKET;

    erl_pkt_len = htons(buffer_len + 1);

    (void)memcpy(size_buf, &erl_pkt_len, sizeof(erl_pkt_len));
    if (bufferevent_write(to_erlang, size_buf, sizeof(size_buf)) < 0) {
        errx(2, "bufferevent_write");
    }

    if (bufferevent_write(to_erlang, buffer, buffer_len) < 0) {
        errx(2, "bufferevent_write");
    }
}

void tap_input(int fd, short event, void *ud) {
    size_t packet_len;
    enet_buf *ep = ud;

    //fprintf(stderr, "Tap read event triggered.\n");

    packet_len = read(tap_fd, ep->buf, ep->len);
    if (packet_len < 0) {
        errx(6, "Couldn't read from the tap.");
    }

    if (packet_len > 0) {
        send_to_erlang(ep->buf, packet_len);
    }
}

void running() {
    u_int16_t erl_pkt_len;
    u_char size_buf[3];

    size_buf[2] = PORT_PROTO_RUNNING;

    erl_pkt_len = htons(1);
    (void)memcpy(size_buf, &erl_pkt_len, sizeof(erl_pkt_len));
    if (bufferevent_write(to_erlang, size_buf, sizeof(size_buf)) < 0) {
        errx(2, "bufferevent_write");
    }
}

void erl_error(struct bufferevent *ev, short event, void *ud) {
    exit(-1);
}

void erlang_init(enet_buf *ep) {
    from_erlang = bufferevent_new(STDIN_FILENO, erl_input, NULL, erl_error, ep);
    if (from_erlang == NULL) {
        errx(2, "bufferevent_new");
    }

    to_erlang = bufferevent_new(STDOUT_FILENO, NULL, NULL, erl_error, ep);
    if (to_erlang == NULL) {
        errx(2, "bufferevent_new");
    }

    bufferevent_setwatermark(from_erlang, EV_READ, 2, 65535);
    bufferevent_enable(from_erlang, EV_READ);
    bufferevent_enable(to_erlang, EV_WRITE);
}

void tap_init(enet_buf *ep) {
    if (tap_fd == STDIN_FILENO || tap_fd == STDOUT_FILENO) {
        errx(8, "BUG: tap filedescriptor is stdin/out for some reason.");
    }
    event_set(&tap, tap_fd, EV_READ | EV_PERSIST, tap_input, ep);
    if (event_add(&tap, NULL) != 0) {
        errx(7, "Couldn't add tap event.");
    }
}

void usage() {
#ifdef __linux__
    fprintf(stderr, "Usage: enet_tap [-b <buffer size>] -i <device>\n");
#else
    fprintf(stderr, "Usage: enet_tap -f <device>\n");
#endif
    exit(1);
}

int main(int argc, char **argv) {
    int ch;
    enet_buf *ep = NULL;

    eb = event_init();

    ep = calloc(1, sizeof(enet_buf));
    if (ep == NULL) {
        err(EXIT_FAILURE, "calloc");
    }

    tap_fd = -1;

#ifdef __linux__
    static struct option longopts[] = {
        { "buffer", required_argument, NULL, 'b' },
        { "device", required_argument, NULL, 'i' },
        { "debug", no_argument, &debug, 'd' },
        { NULL, 0, NULL, 0 }
    };

    // Process options
    while ((ch = getopt_long(argc, argv, "b:i:", longopts, NULL)) != -1) {
        switch (ch) {
        case 'b':
            ep->len = atoi(optarg);
            break;
        case 'i':
            {
                struct ifreq ifr;

                if( (tap_fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
                    err(10, "Couldn't open /dev/net/tun to create device %s.", optarg);
                }

                memset(&ifr, 0, sizeof(ifr));

                /* Flags: IFF_TUN   - TUN device (no Ethernet headers) 
                 *        IFF_TAP   - TAP device  
                 *
                 *        IFF_NO_PI - Do not provide packet information  
                 */ 
                ifr.ifr_flags = IFF_TAP | IFF_NO_PI; 
                strncpy(ifr.ifr_name, optarg, IFNAMSIZ);
                ifr.ifr_name[IFNAMSIZ-1] = '\0';

                if(ioctl(tap_fd, TUNSETIFF, (void *) &ifr) < 0 ){
                    printf("ioctl failed! Errno [%s]", strerror(errno));
                    err(11, "Couldn't create device %s.", optarg);
                }
            }
            break;
        case '?':
        default:
            usage();
        }
    }
    argc -= optind;
    argv += optind;
#else
    /* options descriptor */
    static struct option longopts[] = {
        { "buffer", required_argument, NULL, 'b' },
        { "file", required_argument, NULL, 'f' },
        { "debug", no_argument, &debug, 'd' },
        { NULL, 0, NULL, 0 }
    };

    // Process options
    while ((ch = getopt_long(argc, argv, "b:f:", longopts, NULL)) != -1) {
        switch (ch) {
        case 'b':
            ep->len = atoi(optarg);
            break;
        case 'f':
            //fprintf(stderr, "opening %s.\n", optarg);
            tap_fd = open(optarg, O_RDWR);
            if (tap_fd < 0) {
                err(5, "Couldn't open %s.", optarg);
            }
            break;
        case '?':
        default:
            usage();
        }
    }
    argc -= optind;
    argv += optind;
#endif

    if (tap_fd < 0) {
        errx(5, "No tap device specified");
    }

    /* Empirical testing shows that the smallest MTU allowed
     * on Linux is 68 bytes (+ 3 byte packet header) */
    if (ep->len < 128) {
        ep->len = MAX_PACKET_SIZE;
    }

    ep->buf = calloc(ep->len, 1);
    if (ep->buf == NULL) {
        err(5, "calloc");
    }

    erlang_init(ep);
    tap_init(ep);
    
    running();

    event_loop(0);
    return(0);
}
