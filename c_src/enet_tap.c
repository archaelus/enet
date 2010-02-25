#include <stdlib.h>
#include <event.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <getopt.h>

#ifdef __linux__
#include <net/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <sys/ioctl.h>
#endif

#define MAX_PACKET_SIZE 2048

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

void erl_input(int fd, short event, void *ud) {
    u_char size_buf[2];
    size_t len;
    u_char *data_buf;
    size_t data_read;
    size_t data_written;

    assert(sizeof(u_char) == 1);

    // Read 2 byte data length (unsigned, bigendian)
    if (bufferevent_read(from_erlang, size_buf, 2) != 2) {
        fprintf(stderr, "Couldn't allocate 2 bytes for len?!?\n");
        exit(2);
    }
    len = (size_buf[0] << 8 | size_buf[1]);
    //fprintf(stderr, "Len bytes: %d %d.\n", size_buf[0], size_buf[1]);

    data_buf = malloc(sizeof(u_char) * len);
    if (data_buf == NULL) { 
        fprintf(stderr, "Couldn't allocate %zu bytes for data\n", len);
        exit (3);
    }

    data_read = bufferevent_read(from_erlang, data_buf, len);
    if (data_read != len) {
        fprintf(stderr, "Wanted to read %zu bytes data but got %zu instead\n", len, data_read);
        free(data_buf);
        exit(2);
    }

    //fprintf(stderr, "Writing %zu bytes from erlang to tap.\n", data_read);
    //bufferevent_write(to_erlang, size_buf, 2);
    //bufferevent_write(to_erlang, data_buf, data_read);
    data_written = write(tap_fd, data_buf, data_read);
    if (data_written == -1) {
        perror("write");
    }
    if (data_written != data_read) {
        fprintf(stderr, "Tried to write %zu bytes to the tap, but got %zu instead\n", data_read, data_written);
    }
    free(data_buf);
}

void send_to_erlang(u_char *buffer, size_t buffer_len) {
    size_t erl_pkt_len;
    u_char size_buf[3];

    size_buf[2] = PORT_PROTO_PACKET;

    erl_pkt_len = buffer_len + 1;
    size_buf[1] = erl_pkt_len;
    size_buf[0] = erl_pkt_len >> 8;
    bufferevent_write(to_erlang, size_buf, 3);

    bufferevent_write(to_erlang, buffer, buffer_len);
}

void tap_input(int fd, short event, void *ud) {
    u_char packet_buf[MAX_PACKET_SIZE];
    size_t packet_len;

    //fprintf(stderr, "Tap read event triggered.\n");

    packet_len = read(tap_fd, packet_buf, MAX_PACKET_SIZE);
    if (packet_len < 0) {
        perror("read");
        fprintf(stderr, "Couldn't read from the tap.\n");
        exit(6);
    }

    if (packet_len > 0) {
        send_to_erlang(packet_buf, packet_len);
    }
}

void running() {
    size_t erl_pkt_len;
    u_char size_buf[3];

    size_buf[2] = PORT_PROTO_RUNNING;

    erl_pkt_len = 1;
    size_buf[1] = erl_pkt_len;
    size_buf[0] = erl_pkt_len >> 8;
    bufferevent_write(to_erlang, size_buf, 3);
}

void erl_error(int fd, short event, void *ud) {
    exit(-1);
}

void erlang_init() {
    from_erlang = bufferevent_new(STDIN_FILENO, (evbuffercb)erl_input, NULL, (everrorcb)erl_error, NULL);
    to_erlang = bufferevent_new(STDOUT_FILENO, NULL, NULL, (everrorcb)erl_error, NULL);
    bufferevent_setwatermark(from_erlang, EV_READ, 2, 65535);
    bufferevent_enable(from_erlang, EV_READ);
    bufferevent_enable(to_erlang, EV_WRITE);
}

void tap_init() {
    if (tap_fd == STDIN_FILENO || tap_fd == STDOUT_FILENO) {
        fprintf(stderr, "BUG: tap filedescriptor is stdin/out for some reason.\n");
        exit(8);
    }
    event_set(&tap, tap_fd, EV_READ | EV_PERSIST, tap_input, NULL);
    if (event_add(&tap, NULL) != 0) {
        fprintf(stderr, "Couldn't add tap event.\n");
        exit(7);
    }
}

void usage() {
#ifdef __linux__
    fprintf(stderr, "Usage: enet_tap -i <device>\n");
#else
    fprintf(stderr, "Usage: enet_tap -f <device>\n");
#endif
    exit(1);
}

int main(int argc, char **argv) {
    int ch;

    eb = event_init();

#ifdef __linux__
    static struct option longopts[] = {
        { "device", required_argument, NULL, 'i' },
        { "debug", no_argument, &debug, 'd' },
        { NULL, 0, NULL, 0 }
    };

    // Process options
    while ((ch = getopt_long(argc, argv, "i:", longopts, NULL)) != -1) {
        switch (ch) {
        case 'i':
            {
                struct ifreq ifr;
                int fd, err;

                if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
                    perror("open");
                    fprintf(stderr, "Couldn't open /dev/net/tun to create device %s.\n", optarg);
                    exit(10);
                }

                memset(&ifr, 0, sizeof(ifr));

                /* Flags: IFF_TUN   - TUN device (no Ethernet headers) 
                 *        IFF_TAP   - TAP device  
                 *
                 *        IFF_NO_PI - Do not provide packet information  
                 */ 
                ifr.ifr_flags = IFF_TAP | IFF_NO_PI; 
                strncpy(ifr.ifr_name, optarg, IFNAMSIZ);

                if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
                    fprintf(stderr, "Couldn't create device %s.\n", optarg);
                    exit(11);
                }
                tap_fd = fd;
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
        { "file", required_argument, NULL, 'f' },
        { "debug", no_argument, &debug, 'd' },
        { NULL, 0, NULL, 0 }
    };

    // Process options
    while ((ch = getopt_long(argc, argv, "f:", longopts, NULL)) != -1) {
        switch (ch) {
        case 'f':
            //fprintf(stderr, "opening %s.\n", optarg);
            tap_fd = open(optarg, O_RDWR);
            if (tap_fd < 0) {
                perror("open");
                fprintf(stderr, "Couldn't open %s.\n", optarg);
                exit(5);
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

    erlang_init();
    tap_init();
    
    running();

    event_loop(0);
    return(0);
}
