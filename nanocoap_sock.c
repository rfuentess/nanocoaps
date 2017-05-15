#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "nanocoap.h"
#include "nanocoap_sock.h"
#include "net/sock/udp.h"

#include "dtls.h"
#include "dtls_debug.h"
#include "tinydtls.h"

#if NANOCOAP_DEBUG
#define ENABLE_DEBUG (1)
#else
#define ENABLE_DEBUG (0)
#endif
#include "debug.h"

extern dtls_context_t * init_dtls(dtls_remote_peer_t * remote_peer);
extern void dtls_handle_read_sock(dtls_context_t *ctx, uint8_t *packet,
                                                            size_t size);

ssize_t nanocoap_get(sock_udp_ep_t *remote, const char *path, uint8_t *buf, size_t len)
{
    ssize_t res;
    sock_udp_t sock;

    if (!remote->port) {
        remote->port = COAP_PORT;
    }

    res = sock_udp_create(&sock, NULL, remote, 0);
    if (res < 0) {
        return res;
    }

    uint8_t *pktpos = buf;
    pktpos += coap_build_hdr((coap_hdr_t *)pktpos, COAP_REQ, NULL, 0, COAP_METHOD_GET, 1);
    pktpos += coap_put_option_url(pktpos, 0, path);

    /* TODO: timeout random between between ACK_TIMEOUT and (ACK_TIMEOUT *
     * ACK_RANDOM_FACTOR) */
    uint32_t timeout = COAP_ACK_TIMEOUT * (1000000U);
    int tries = 0;
    while (tries++ < COAP_MAX_RETRANSMIT) {
        if(!tries) {
            DEBUG("nanocoap: maximum retries reached.\n");
            res = -ETIMEDOUT;
            goto out;
        }

        res = sock_udp_send(&sock, buf, pktpos-buf, NULL);
        if (res <= 0) {
            DEBUG("nanocoap: error sending coap request\n");
            goto out;
        }

        res = sock_udp_recv(&sock, buf, len, timeout, NULL);
        if (res <= 0) {
            if (res == -ETIMEDOUT) {
                DEBUG("nanocoap: timeout\n");

                timeout *= 2;
                continue;
            }
            DEBUG("nanocoap: error receiving coap request\n");
            break;
        }

        coap_pkt_t pkt;
        if (coap_parse(&pkt, (uint8_t*)buf, res) < 0) {
            puts("error parsing packet");
            continue;
        }
        else {
            res = coap_get_code(&pkt);
            if (res != 205) {
                res = -res;
            }
            else {
                if (pkt.payload_len) {
                    memcpy(buf, pkt.payload, pkt.payload_len);
                }
                res = pkt.payload_len;
            }
            break;
        }
    }

out:
    sock_udp_close(&sock);

    return res;
}

int nanocoap_server(sock_udp_ep_t *local, uint8_t *buf, size_t bufsize)
{
    sock_udp_t sock;
    dtls_context_t *dtls_context = NULL;
    sock_udp_ep_t remote;
    dtls_remote_peer_t remote_peer;

    remote_peer.sock = &sock;
    remote_peer.remote = &remote;

    dtls_init(); /*TinyDTLS mandatory settings*/

    /*
     *  TODO: Create two threads: One for CoAP and another for CoAPS
     *  A standrad server should be able to get non-secure requests
     *  toghether to secure requests.
     */
    if (!local->port) {
        local->port = COAPS_PORT;
    }

    DEBUG("Listening to port %i",local->port );

    ssize_t res = sock_udp_create(&sock, local, NULL, 0);
    if (res == -1) {
        return -1;
    }

    dtls_context = init_dtls(&remote_peer);

    if (!dtls_context){
      return -1;
    }

    while(1) {
        ssize_t res = sock_udp_recv(&sock, buf, bufsize, SOCK_NO_TIMEOUT, &remote);
        /*TODO: This should be more exhaustive */
        if (res == -1) {
            DEBUG("error receiving UDP packet\n");
            return -1;
        }
        else {
          dtls_handle_read_sock(dtls_context, (uint8_t*)buf, res );
        }
    }/* While(1) */

    return 0;
}
