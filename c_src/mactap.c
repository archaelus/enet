#include <stdlib.h>
#include <event.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>

#define MAX_PACKET_SIZE 2048

/*

Packet,2 protocol on STDIN/STDOUT

*/

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
        fprintf(stderr, "Couldn't allocate %d bytes for data\n", len);
        exit (3);
    }

    data_read = bufferevent_read(from_erlang, data_buf, len);
    if (data_read != len) {
        fprintf(stderr, "Wanted to read %d bytes data but got %d instead\n", len, data_read);
        free(data_buf);
        exit(2);
    }

    fprintf(stderr, "Writing %d bytes from erlang to tap.\n", data_read);
    //bufferevent_write(to_erlang, size_buf, 2);
    //bufferevent_write(to_erlang, data_buf, data_read);
    data_written = write(tap_fd, data_buf, data_read);
    if (data_written == -1) {
        perror("write");
    }
    if (data_written != data_read) {
        fprintf(stderr, "Tried to write %d bytes to the tap, but got %d instead\n", data_read, data_written);
    }
    free(data_buf);
}

void tap_input(int fd, short event, void *ud) {
    u_char packet_buf[MAX_PACKET_SIZE];
    size_t packet_len;
    u_char size_buf[2];

    fprintf(stderr, "Tap read event triggered.\n");

    packet_len = read(tap_fd, packet_buf, MAX_PACKET_SIZE);
    if (packet_len < 0) {
        perror("read");
        fprintf(stderr, "Couldn't read from the tap.\n");
        exit(6);
    }
    if (packet_len > 0) {
        size_buf[1] = packet_len;
        size_buf[0] = packet_len >> 8;
        bufferevent_write(to_erlang, size_buf, 2);
        bufferevent_write(to_erlang, packet_buf, packet_len);
    }
}

void erl_error(int fd, short event, void *ud) {
    exit(-1);
}

void erlang_init() {
    from_erlang = bufferevent_new(STDIN_FILENO, erl_input, NULL, erl_error, NULL);
    to_erlang = bufferevent_new(STDOUT_FILENO, NULL, NULL, erl_error, NULL);
    bufferevent_setwatermark(from_erlang, EV_READ, 2, 65535);
    bufferevent_enable(from_erlang, EV_READ);
    bufferevent_enable(to_erlang, EV_WRITE);
}

void tap_init() {
    /*
    u_char arp_request[] = {138,126,111,148,93,233,255,255,255,255,255,255,8,6,0,1,
                            8,0,6,4,0,1,138,126,111,148,93,233,192,168,3,2,0,0,0,0,
                            0,0,192,168,3,1};
    int save_tap_fd;
    */
    tap_fd = open("/dev/tap0", O_RDWR);
    //save_tap_fd = tap_fd;

    if (tap_fd < 0) {
        perror("open");
        fprintf(stderr, "Couldn't open /dev/tap0.\n");
        exit(5);
    }
    //fprintf(stderr, "Opened /dev/tap0 as %d.\nSleeping for 30s for debugging.\n", tap_fd);

    event_set(&tap, tap_fd, EV_READ | EV_PERSIST, tap_input, NULL);
    if (event_add(&tap, NULL) != 0) {
        fprintf(stderr, "Couldn't add tap event.\n");
        exit(7);
    }
    //fprintf(stderr, "Added read event for /dev/tap0.\n");
    /*
    fprintf(stderr, "/dev/tap0 FD is now %d (was %d).\nSleeping for 30s for debugging.\n", tap_fd, save_tap_fd);
    sleep(30);

    if (write(tap_fd, arp_request, 42) != 42) {
        perror("write");
        fprintf(stderr, "Couldn't write arp request to /dev/tap0.\n");
        exit(10);
    }
    fprintf(stderr, "Wrote arp request to /dev/tap0.\n");
    */
}

int main() {
    eb = event_init();
    fprintf(stderr, "Libevent initialized using method '%s'.\n", event_base_get_method(eb));
    erlang_init();
    tap_init();
    
    event_loop(0);
    return(0);
}
