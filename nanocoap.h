#ifndef NANOCOAP_H
#define NANOCOAP_H

#include <assert.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "net/sock/udp.h"

#define COAP_PORT               (5683)
#define COAPS_PORT              (20220)
#define NANOCOAP_URL_MAX        (64)

#define COAP_OPT_URI_HOST       (3)
#define COAP_OPT_OBSERVE        (6)
#define COAP_OPT_URI_PATH       (11)
#define COAP_OPT_CONTENT_FORMAT (12)

#define COAP_REQ                (0)
#define COAP_RESP               (2)
#define COAP_RST                (3)

/**
 * @name Message types -- confirmable, non-confirmable, etc.
 * @{
 */
#define COAP_TYPE_CON           (0)
#define COAP_TYPE_NON           (1)
#define COAP_TYPE_ACK           (2)
#define COAP_TYPE_RST           (3)
/** @} */

/**
 * @name CoAP method codes used in header
 * @{
 */
#define COAP_CLASS_REQ          (0)
#define COAP_METHOD_GET         (1)
#define COAP_METHOD_POST        (2)
#define COAP_METHOD_PUT         (3)
#define COAP_METHOD_DELETE      (4)
/** @} */

/**
 * @name CoAP method flags used in coap_handlers array
 * @{
 */
#define COAP_GET                (0x1)
#define COAP_POST               (0x2)
#define COAP_PUT                (0x4)
#define COAP_DELETE             (0x8)
/** @} */

#define COAP_CODE_EMPTY         (0)

/**
 * @name Response message codes: success
 * @{
 */
#define COAP_CLASS_SUCCESS      (2)
#define COAP_CODE_CREATED      ((2<<5) | 1)
#define COAP_CODE_DELETED      ((2<<5) | 2)
#define COAP_CODE_VALID        ((2<<5) | 3)
#define COAP_CODE_CHANGED      ((2<<5) | 4)
#define COAP_CODE_CONTENT      ((2<<5) | 5)
#define COAP_CODE_205          ((2<<5) | 5)
/** @} */
/**
 * @name Response message codes: client error
 * @{
 */
#define COAP_CLASS_CLIENT_FAILURE             (4)
#define COAP_CODE_BAD_REQUEST                ((4<<5) | 0)
#define COAP_CODE_UNAUTHORIZED               ((4<<5) | 1)
#define COAP_CODE_BAD_OPTION                 ((4<<5) | 2)
#define COAP_CODE_FORBIDDEN                  ((4<<5) | 3)
#define COAP_CODE_PATH_NOT_FOUND             ((4<<5) | 4)
#define COAP_CODE_404                        ((4<<5) | 4)
#define COAP_CODE_METHOD_NOT_ALLOWED         ((4<<5) | 5)
#define COAP_CODE_NOT_ACCEPTABLE             ((4<<5) | 6)
#define COAP_CODE_PRECONDITION_FAILED        ((4<<5) | 0xC)
#define COAP_CODE_REQUEST_ENTITY_TOO_LARGE   ((4<<5) | 0xD)
#define COAP_CODE_UNSUPPORTED_CONTENT_FORMAT ((4<<5) | 0xF)
/** @} */
/**
 * @name Response message codes: server error
 * @{
 */
#define COAP_CLASS_SERVER_FAILURE             (5)
#define COAP_CODE_INTERNAL_SERVER_ERROR      ((5<<5) | 0)
#define COAP_CODE_NOT_IMPLEMENTED            ((5<<5) | 1)
#define COAP_CODE_BAD_GATEWAY                ((5<<5) | 2)
#define COAP_CODE_SERVICE_UNAVAILABLE        ((5<<5) | 3)
#define COAP_CODE_GATEWAY_TIMEOUT            ((5<<5) | 4)
#define COAP_CODE_PROXYING_NOT_SUPPORTED     ((5<<5) | 5)
/** @} */

#define COAP_CT_LINK_FORMAT     (40)
#define COAP_CT_XML             (41)
#define COAP_CT_OCTET_STREAM    (42)
#define COAP_CT_EXI             (47)
#define COAP_CT_JSON            (50)

/**
 * @name Content-Format option codes
 * @{
 */
#define COAP_FORMAT_TEXT         (0)
#define COAP_FORMAT_LINK        (40)
#define COAP_FORMAT_OCTET       (42)
#define COAP_FORMAT_JSON        (50)
#define COAP_FORMAT_CBOR        (60)
/** @brief nanocoap-specific value to indicate no format specified. */
#define COAP_FORMAT_NONE     (65535)
/** @} */

/**
 * @name Observe (RFC 7641) constants
 * @{
 */
#define COAP_OBS_REGISTER        (0)
#define COAP_OBS_DEREGISTER      (1)
/** @} */

#define COAP_ACK_TIMEOUT        (2U)
#define COAP_RANDOM_FACTOR      (1.5)
#define COAP_MAX_RETRANSMIT     (4)
#define COAP_NSTART             (1)
#define COAP_DEFAULT_LEISURE    (5)

typedef struct {
  sock_udp_t *sock;
  sock_udp_ep_t *remote;
} dtls_remote_peer_t;


typedef struct {
    uint8_t ver_t_tkl;
    uint8_t code;
    uint16_t id;
    uint8_t data[];
} coap_hdr_t;

typedef struct {
    coap_hdr_t *hdr;
    uint8_t url[NANOCOAP_URL_MAX];
    uint8_t *token;
    uint8_t *payload;
    unsigned payload_len;
    uint16_t content_type;
    uint32_t observe_value;
} coap_pkt_t;

typedef ssize_t (*coap_handler_t)(coap_pkt_t* pkt, uint8_t *buf, size_t len);

typedef struct {
    const char *path;
    unsigned methods;
    coap_handler_t handler;
} coap_resource_t;

extern const coap_resource_t coap_resources[];
extern const unsigned coap_resources_numof;

int coap_parse(coap_pkt_t* pkt, uint8_t *buf, size_t len);
ssize_t coap_build_reply(coap_pkt_t *pkt, unsigned code,
        uint8_t *rbuf, unsigned rlen, unsigned payload_len);

ssize_t coap_reply_simple(coap_pkt_t *pkt,
        unsigned code,
        uint8_t *buf, size_t len,
        unsigned ct,
        const uint8_t *payload, uint8_t payload_len);

ssize_t coap_handle_req(coap_pkt_t *pkt, uint8_t *resp_buf, unsigned resp_buf_len);

ssize_t coap_build_hdr(coap_hdr_t *hdr, unsigned type, uint8_t *token, size_t token_len, unsigned code, uint16_t id);
size_t coap_put_option(uint8_t *buf, uint16_t lastonum, uint16_t onum, uint8_t *odata, size_t olen);
size_t coap_put_option_ct(uint8_t *buf, uint16_t lastonum, uint16_t content_type);
size_t coap_put_option_url(uint8_t *buf, uint16_t lastonum, const char *url);

static inline unsigned coap_get_ver(coap_pkt_t *pkt)
{
    return (pkt->hdr->ver_t_tkl & 0x60) >> 6;
}

static inline unsigned coap_get_type(coap_pkt_t *pkt)
{
    return (pkt->hdr->ver_t_tkl & 0x30) >> 4;
}

static inline unsigned coap_get_token_len(coap_pkt_t *pkt)
{
    return (pkt->hdr->ver_t_tkl & 0xf);
}

static inline unsigned coap_get_code_class(coap_pkt_t *pkt)
{
    return pkt->hdr->code >> 5;
}

static inline unsigned coap_get_code_detail(coap_pkt_t *pkt)
{
    return pkt->hdr->code & 0x1f;
}

static inline unsigned coap_get_code(coap_pkt_t *pkt)
{
    return (coap_get_code_class(pkt) * 100) + coap_get_code_detail(pkt);
}

static inline unsigned coap_get_id(coap_pkt_t *pkt)
{
    return ntohs(pkt->hdr->id);
}

static inline unsigned coap_get_total_hdr_len(coap_pkt_t *pkt)
{
    return sizeof(coap_hdr_t) + coap_get_token_len(pkt);
}

static inline uint8_t coap_code(unsigned class, unsigned detail)
{
   return (class << 5) | detail;
}

static inline void coap_hdr_set_code(coap_hdr_t *hdr, uint8_t code)
{
    hdr->code = code;
}

static inline void coap_hdr_set_type(coap_hdr_t *hdr, unsigned type)
{
    /* assert correct range of type */
    assert(!(type & ~0x3));

    hdr->ver_t_tkl &= ~0x30;
    hdr->ver_t_tkl |= type << 4;
}

static inline unsigned coap_method2flag(unsigned code)
{
    return (1<<(code-1));
}

/**
 * @brief  Identifies a packet containing an Observe option.
 */
static inline bool coap_has_observe(coap_pkt_t *pkt)
{
    return pkt->observe_value != UINT32_MAX;
}

/**
 * @brief  Clears the Observe option value from a packet.
 */
static inline void coap_clear_observe(coap_pkt_t *pkt)
{
    pkt->observe_value = UINT32_MAX;
}

/**
 * @brief  Provides the value for the Observe option in a packet.
 */
static inline uint32_t coap_get_observe(coap_pkt_t *pkt)
{
    return pkt->observe_value;
}

extern ssize_t coap_well_known_core_default_handler(coap_pkt_t* pkt, \
                                                    uint8_t *buf, size_t len);

#define COAP_WELL_KNOWN_CORE_DEFAULT_HANDLER \
    { "/.well-known/core", COAP_GET, coap_well_known_core_default_handler }

#endif /* NANOCOAP_H */