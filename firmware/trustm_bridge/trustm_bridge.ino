/*
 * trustm_bridge - a USB CDC command bridge to an OPTIGA Trust M.
 *
 * The Infineon host library stays here on the RP2040; the desktop drives it one
 * line at a time. See ../../bridge-plan.md section 3 for the design.
 *
 * Wire protocol (ASCII, newline terminated):
 *
 *   [>] [tag] <CMD> [arg ...]         command, from the host
 *   < <tag> OK <CMD> [token ...]      reply
 *   < <tag> ERR <CMD> <status-hex> <stage>
 *   # <free text>                     unsolicited note, safe to ignore
 *
 * The '>' prefix, any space after it, and the tag are all optional, so that
 * "RAND 32" typed at a serial monitor works as well as "> 7 RAND 32" sent by
 * the host library. A tag is any leading token starting with a digit; command
 * names never do, which is what keeps the two apart. It is echoed back
 * verbatim - the firmware never parses it - and becomes '-' when absent.
 *
 * The tag is a correlation tag, not a sequence number: it answers "which of my
 * requests is this?", so that a reply to a command the host already timed out
 * on is discarded rather than mistaken for the answer to the next one. The
 * echoed command is a second, independent check on the same thing, and makes a
 * raw capture readable without scrolling back to find the request.
 *
 * This sketch deliberately does NOT use the IFX_OPTIGA_TrustM C++ wrapper. The
 * wrapper collapses every failure to 1 and hardcodes TRNG; talking to
 * optiga_util_* / optiga_crypt_* directly keeps the real optiga_lib_status_t
 * and gives access to the whole API. It also skips the wrapper's pairMCU(),
 * so nothing is ever written to the platform binding secret.
 *
 * Commands implemented so far: PING, UID, RAND, RDATA, WDATA, RMETA, WMETA,
 * KEYGEN, SIGN, VERIFY, HASH (one-shot and streaming), ECDH, CTRINC, RSAGEN,
 * RSASIGN, HELP.
 */

#include "OPTIGATrustM.h"
#include "optiga_trustm/optiga_lib_version.h"

#define BRIDGE_PROTO      2
#define BRIDGE_VERSION    "0.6.0"

#define MAX_LINE          4096      /* matches the host's MAX_LINE */
#define MAX_ARGS          8
#define UID_LENGTH        27

/* The tag is echoed into the reply, so it needs a ceiling of its own or a
 * 4 KB line of digits would come straight back out. Anything a host sensibly
 * uses - a counter, a UUID fragment - fits easily. */
#define TAG_MAX           32

/* GetRandom accepts 0x0008-0x0100 bytes of stream (SRM 4.4.1.6). The host
 * chunks anything larger and pads anything smaller. */
#define RAND_LEN_MIN      8
#define RAND_LEN_MAX      256
#define RAND_LEN_DEFAULT  64

/* Ceiling on one RDATA/WDATA transfer. Two limits sit above it: the chip's
 * OPTIGA_MAX_COMMS_BUFFER_SIZE (1557) and MAX_LINE, since hex doubles the
 * payload. 1024 clears both with room for the reply's own tokens, and the
 * host chunks anything larger. */
#define DATA_LEN_MAX      1024

#define CHIP_TIMEOUT_MS   10000

/* Bridge-level failures, in a range optiga_lib_status_t never uses (its
 * device errors top out at 0x80FF). Keep in sync with BRIDGE_ERRORS in
 * trustm/const.py. */
#define E_CMD             0xFF01    /* unknown command                */
#define E_ARGS            0xFF02    /* wrong argument count           */
#define E_RANGE           0xFF03    /* argument outside allowed range */
#define E_OVERFLOW        0xFF04    /* line longer than MAX_LINE      */
#define E_TIMEOUT         0xFF05    /* chip never completed           */
#define E_STATE           0xFF06    /* command needs a state that is not set */

/* Shared by RDATA and WDATA: only one command runs at a time, and 1 KB is
 * worth keeping off the stack. */
static uint8_t data_buf[DATA_LEN_MAX];

static optiga_util_t  *me_util  = NULL;
static optiga_crypt_t *me_crypt = NULL;
static bool            chip_open = false;

static volatile optiga_lib_status_t bridge_status;

static void bridge_callback(void *context, optiga_lib_status_t return_status)
{
  (void)context;
  bridge_status = return_status;
}

/*
 * Every optiga_* call is asynchronous: it returns immediately and the callback
 * lands later, so each one has to be pumped to completion here. The library's
 * own OPTIGA_ASSERT_WAIT_WHILE_BUSY macro spins forever if the chip goes away;
 * this version gives up, because a wedged bridge is much worse than an error.
 */
static optiga_lib_status_t wait_busy(optiga_lib_status_t return_status)
{
  if (OPTIGA_LIB_SUCCESS != return_status) {
    return return_status;
  }

  uint32_t start = millis();
  while (OPTIGA_LIB_BUSY == bridge_status) {
    pal_os_event_process();
    if (millis() - start > CHIP_TIMEOUT_MS) {
      return E_TIMEOUT;
    }
  }
  return bridge_status;
}

/*
 * Opened lazily rather than in setup(): the chip is not touched until a command
 * needs it, so the board always enumerates and always answers PING even if the
 * shield is missing or dead.
 */
static optiga_lib_status_t chip_ensure_open(void)
{
  if (chip_open) {
    return OPTIGA_LIB_SUCCESS;
  }

  if (NULL == me_util) {
    me_util = optiga_util_create(OPTIGA_INSTANCE_ID_0, bridge_callback, NULL);
    if (NULL == me_util) {
      return OPTIGA_UTIL_ERROR;
    }
  }
  if (NULL == me_crypt) {
    me_crypt = optiga_crypt_create(OPTIGA_INSTANCE_ID_0, bridge_callback, NULL);
    if (NULL == me_crypt) {
      return OPTIGA_CRYPT_ERROR;
    }
  }

  bridge_status = OPTIGA_LIB_BUSY;
  optiga_lib_status_t rs = wait_busy(optiga_util_open_application(me_util, 0));
  if (OPTIGA_LIB_SUCCESS == rs) {
    chip_open = true;
  }
  return rs;
}

/* ---------------------------------------------------------------- replies */

/* The tag and command of whatever is being answered right now. Only one
 * command ever runs at a time - the same invariant that lets RDATA and WDATA
 * share data_buf - so holding them here instead of threading them through
 * every cmd_* signature costs nothing and keeps the reply shape in one place.
 * cur_tag points into line[], which stays valid until the next line arrives;
 * cur_cmd is always a literal, so an unknown command cannot be echoed back at
 * arbitrary length. */
static const char *cur_tag = "-";
static const char *cur_cmd = "-";

static void reply_begin(void)
{
  Serial.print("< ");
  Serial.print(cur_tag);
  Serial.print(' ');
}

static void reply_ok(void)
{
  reply_begin();
  Serial.print("OK ");
  Serial.print(cur_cmd);
  Serial.print(' ');
}

static void reply_err(uint16_t status, const char *stage)
{
  char buf[8];
  snprintf(buf, sizeof(buf), "0x%04X", status);
  reply_begin();
  Serial.print("ERR ");
  Serial.print(cur_cmd);
  Serial.print(' ');
  Serial.print(buf);
  Serial.print(' ');
  Serial.println(stage);
}

static void print_hex(const uint8_t *data, uint16_t length)
{
  static const char digits[] = "0123456789ABCDEF";
  char chunk[65];
  uint8_t n = 0;

  for (uint16_t i = 0; i < length; i++) {
    chunk[n++] = digits[data[i] >> 4];
    chunk[n++] = digits[data[i] & 0x0F];
    if (n >= sizeof(chunk) - 1) {
      chunk[n] = '\0';
      Serial.print(chunk);
      n = 0;
    }
  }
  chunk[n] = '\0';
  Serial.print(chunk);
}

/* OPTIGA_LIB_VERSION is "Ver 1.30.885" and a reply token cannot contain a
 * space, so hand back just the number. */
static const char *lib_version(void)
{
  const char *v  = OPTIGA_LIB_VERSION;
  const char *sp = strrchr(v, ' ');
  return sp ? sp + 1 : v;
}

/* ---------------------------------------------------------------- parsing */

/* strtoul alone accepts trailing junk and silently saturates, so every
 * conversion goes through here and a malformed argument becomes E_ARGS rather
 * than a plausible wrong number. */
static bool parse_u16(const char *text, int base, uint16_t *out)
{
  char *end = NULL;
  unsigned long value = strtoul(text, &end, base);

  if (end == text || *end != '\0' || value > 0xFFFF) {
    return false;
  }
  *out = (uint16_t)value;
  return true;
}

static int hex_nibble(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* Decodes hex into `out` and returns the byte count. The two ways it can fail
 * are told apart, because "your payload is malformed" and "your payload is too
 * big" want completely different things done about them. */
#define HEX_MALFORMED   (-1)    /* bad character, or an odd number of digits */
#define HEX_TOO_LONG    (-2)    /* would not fit in `max` bytes             */

static int32_t parse_hex(const char *text, uint8_t *out, uint16_t max)
{
  uint32_t n = 0;

  while (*text) {
    int hi = hex_nibble(text[0]);
    int lo = (text[1] != '\0') ? hex_nibble(text[1]) : -1;

    if (hi < 0 || lo < 0) {
      return HEX_MALFORMED;
    }
    if (n >= max) {
      return HEX_TOO_LONG;
    }
    out[n++] = (uint8_t)((hi << 4) | lo);
    text += 2;
  }
  return (int32_t)n;
}

/* --------------------------------------------------------------- commands */

static void cmd_ping(void)
{
  reply_ok();
  Serial.print("proto=");
  Serial.print(BRIDGE_PROTO);
  Serial.print(" fw=trustm_bridge/" BRIDGE_VERSION);
  Serial.print(" lib=");
  Serial.print(lib_version());
  Serial.print(" maxline=");
  Serial.print(MAX_LINE);
  Serial.print(" maxrand=");
  Serial.print(RAND_LEN_MAX);
  Serial.print(" maxdata=");
  Serial.print(DATA_LEN_MAX);
  Serial.print(" open=");
  Serial.println(chip_open ? 1 : 0);
}

static void cmd_uid(void)
{
  optiga_lib_status_t rs = chip_ensure_open();
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "open");
    return;
  }

  uint8_t  uid[UID_LENGTH];
  uint16_t length = sizeof(uid);

  bridge_status = OPTIGA_LIB_BUSY;
  rs = wait_busy(optiga_util_read_data(me_util, eCOPROCESSOR_UID, 0, uid, &length));
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "read");
    return;
  }

  reply_ok();
  print_hex(uid, length);
  Serial.println();
}

/*
 * HELP, ?
 *
 * The prose goes out as '#' notes, which every host already ignores, and the
 * OK line carries just the command names - so the same command serves a human
 * reading a serial monitor and a program asking what this firmware supports.
 */
static void cmd_help(void)
{
  Serial.println("# trustm_bridge/" BRIDGE_VERSION " - OPTIGA Trust M command bridge");
  Serial.println("#");
  Serial.println("# Syntax:  [>] [tag] COMMAND [arg ...]");
  Serial.println("#   '>' and the tag are optional; a tag must start with a digit and is");
  Serial.println("#   echoed back, or '-' when absent. Programs should always send one.");
  Serial.println("#     > 7 RAND 32   ->  < 7 OK RAND 9F2C...");
  Serial.println("#     RAND 32       ->  < - OK RAND 9F2C...");
  Serial.println("#");
  Serial.println("# PING                                      versions, limits, chip state");
  Serial.println("# UID                                       coprocessor UID (OID E0C2)");
  Serial.println("# RAND [len] [trng|drng]                    either may be omitted; 64, trng");
  Serial.println("# TRNG [len] / DRNG [len]                   RAND with the source fixed");
  Serial.println("# RDATA <oid> [offset] [len]                read a data object");
  Serial.println("# WDATA <oid> <offset> <hex> [write|erase]  write a data object");
  Serial.println("# RMETA <oid>                              read an object's metadata");
  Serial.println("# WMETA <oid> <hex>                        write it back (one-way!)");
  Serial.println("# KEYGEN <slot|session|export> [curve] [usage]   generate an ECC keypair");
  Serial.println("# SIGN <slot|session> <digest-hex>          ECDSA over a digest");
  Serial.println("# VERIFY <curve> <pubkey> <digest> <sig>   ECDSA verify on the chip");
  Serial.println("# HASH <hex>                               SHA-256 on the chip");
  Serial.println("# HASHSTART / HASHUPD <hex> / HASHFIN      streaming SHA-256");
  Serial.println("# ECDH <slot|session> <curve> <peer-pub>   key agreement");
  Serial.println("# CTRINC <oid> [step]                      bump a monotonic counter");
  Serial.println("# RSAGEN <slot> <1024|2048> [usage]        RSA keypair (SKU-dependent)");
  Serial.println("# RSASIGN <slot> <digest> [sha256|sha384]  RSA signature");
  Serial.println("# HELP / ?                                  this text");
  Serial.println("#");
  Serial.println("# len is 8-256, oid is 4 hex digits, RDATA/WDATA move <=1024 bytes a call.");
  Serial.println("# RDATA's len is a ceiling: the chip returns what the object holds.");
  Serial.println("# curve p256|p384, usage sign|auth|agree|encrypt joined by '+'.");
  Serial.println("# SIGN returns r,s WITHOUT the outer DER SEQUENCE. See trustm.md.");
  Serial.println("# WDATA and KEYGEN can destroy the chip's factory identity.");
  Serial.println("# WMETA can lock an object permanently. LcsO only ever goes forward.");

  reply_ok();
  Serial.println("PING UID RAND TRNG DRNG RDATA WDATA RMETA WMETA KEYGEN SIGN "
                 "VERIFY HASH HASHSTART HASHUPD HASHFIN ECDH CTRINC "
                 "RSAGEN RSASIGN HELP");
}

/*
 * RAND [len] [trng|drng],  TRNG [len],  DRNG [len]
 *
 * TRNG and DRNG are RAND with the source already chosen, so they take a length
 * and nothing else: a source argument after one of them would contradict the
 * command name, and quietly letting one of the two win is worse than saying so.
 *
 * Every form defaults to 64 bytes, which is a useful amount of key material and
 * comfortably inside the chip's 8..256 window.
 */
static void cmd_rand(int argc, char **argv, optiga_rng_type_t rng_type,
                     bool source_locked)
{
  uint16_t length = RAND_LEN_DEFAULT;
  int      i      = 0;

  /* Both arguments are optional, so neither can be found by position alone:
   * "RAND drng" has to be recognised by its argument not being a number. A
   * length is anything starting with a digit, which also keeps "32x" an
   * E_ARGS rather than a silent 32. */
  if (i < argc && isdigit((unsigned char)argv[i][0])) {
    if (!parse_u16(argv[i], 10, &length)) {
      reply_err(E_ARGS, "rand");
      return;
    }
    if (length < RAND_LEN_MIN || length > RAND_LEN_MAX) {
      reply_err(E_RANGE, "rand");
      return;
    }
    i++;
  }
  if (i < argc) {
    /* TRNG and DRNG already said which source; naming one here either repeats
     * it or contradicts it, and neither is worth guessing at. */
    if (source_locked) { reply_err(E_ARGS, "rand"); return; }
    if      (!strcasecmp(argv[i], "trng")) rng_type = OPTIGA_RNG_TYPE_TRNG;
    else if (!strcasecmp(argv[i], "drng")) rng_type = OPTIGA_RNG_TYPE_DRNG;
    else { reply_err(E_ARGS, "rand"); return; }
    i++;
  }
  /* Anything left over is a trailing argument or the two in the wrong order. */
  if (i != argc) {
    reply_err(E_ARGS, "rand");
    return;
  }

  optiga_lib_status_t rs = chip_ensure_open();
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "open");
    return;
  }

  uint8_t random[RAND_LEN_MAX];
  bridge_status = OPTIGA_LIB_BUSY;
  rs = wait_busy(optiga_crypt_random(me_crypt, rng_type, random, length));
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "random");
    return;
  }

  reply_ok();
  print_hex(random, length);
  Serial.println();
}

/*
 * RDATA <oid> [offset] [len]
 *
 * `len` is a ceiling, not a demand: the chip returns however much the object
 * actually holds from `offset`, which is how a certificate of unknown size is
 * read in one go. Omitting it asks for the largest transfer the bridge can
 * frame.
 */
static void cmd_rdata(int argc, char **argv)
{
  if (argc < 1 || argc > 3) {
    reply_err(E_ARGS, "rdata");
    return;
  }

  uint16_t oid;
  uint16_t offset = 0;
  uint16_t length = DATA_LEN_MAX;

  if (!parse_u16(argv[0], 16, &oid)) {
    reply_err(E_ARGS, "rdata");
    return;
  }
  if (argc >= 2 && !parse_u16(argv[1], 10, &offset)) {
    reply_err(E_ARGS, "rdata");
    return;
  }
  if (argc >= 3) {
    if (!parse_u16(argv[2], 10, &length)) {
      reply_err(E_ARGS, "rdata");
      return;
    }
    if (length == 0 || length > DATA_LEN_MAX) {
      reply_err(E_RANGE, "rdata");
      return;
    }
  }

  optiga_lib_status_t rs = chip_ensure_open();
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "open");
    return;
  }

  uint16_t got = length;
  bridge_status = OPTIGA_LIB_BUSY;
  rs = wait_busy(optiga_util_read_data(me_util, oid, offset, data_buf, &got));
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "read");
    return;
  }

  reply_ok();
  print_hex(data_buf, got);
  Serial.println();
}

/*
 * WDATA <oid> <offset> <hex> [write|erase]
 *
 * `write` (the default) is OPTIGA_UTIL_WRITE_ONLY, which overwrites the bytes
 * at `offset` and leaves the rest of the object alone; `erase` is
 * OPTIGA_UTIL_ERASE_AND_WRITE, which discards the object first so its length
 * becomes exactly what was written.
 *
 * There is no guard here on which OID gets written - the firmware stays a
 * complete mapping of the API, and refusing the factory-provisioned objects is
 * TrustM.write_data()'s job. Driving this command by hand can destroy the
 * chip's identity permanently.
 */
static void cmd_wdata(int argc, char **argv)
{
  if (argc < 3 || argc > 4) {
    reply_err(E_ARGS, "wdata");
    return;
  }

  uint16_t oid;
  uint16_t offset;

  if (!parse_u16(argv[0], 16, &oid) || !parse_u16(argv[1], 10, &offset)) {
    reply_err(E_ARGS, "wdata");
    return;
  }

  uint8_t write_type = OPTIGA_UTIL_WRITE_ONLY;
  if (argc == 4) {
    if      (!strcasecmp(argv[3], "write")) write_type = OPTIGA_UTIL_WRITE_ONLY;
    else if (!strcasecmp(argv[3], "erase")) write_type = OPTIGA_UTIL_ERASE_AND_WRITE;
    else { reply_err(E_ARGS, "wdata"); return; }
  }

  int32_t length = parse_hex(argv[2], data_buf, DATA_LEN_MAX);
  if (HEX_TOO_LONG == length) {
    reply_err(E_RANGE, "wdata");
    return;
  }
  if (length < 0) {
    reply_err(E_ARGS, "wdata");
    return;
  }
  /* Whitespace tokenising means an empty payload cannot actually reach here -
   * the token simply vanishes and the argument count is wrong instead. The
   * guard stands anyway, so that WDATA never turns into a zero-length write. */
  if (0 == length) {
    reply_err(E_RANGE, "wdata");
    return;
  }

  optiga_lib_status_t rs = chip_ensure_open();
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "open");
    return;
  }

  bridge_status = OPTIGA_LIB_BUSY;
  rs = wait_busy(optiga_util_write_data(me_util, oid, write_type, offset,
                                        data_buf, (uint16_t)length));
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "write");
    return;
  }

  reply_ok();
  Serial.println(length);
}

/* --------------------------------------------------------------- metadata */

/* Metadata is a small constructed TLV - the largest in the V1 factory dump is
 * 17 bytes - but optiga_util_write_metadata takes a uint8_t length, so 255 is
 * the real ceiling and there is no reason to sit near it. */
#define META_MAX          128

/*
 * RMETA <oid>
 *
 * Returns the object's metadata as one hex token: a constructed TLV under tag
 * 0x20, holding the lifecycle state, sizes, access conditions and type. The
 * firmware does not decode it - trustm/metadata.py does, where the SRM's tables
 * can be kept alongside the code that uses them.
 *
 * Reading metadata is always permitted. It is reading the object's *contents*
 * that the access conditions govern, which is why this works on objects RDATA
 * refuses.
 */
static void cmd_rmeta(int argc, char **argv)
{
  if (argc != 1) {
    reply_err(E_ARGS, "rmeta");
    return;
  }

  uint16_t oid;
  if (!parse_u16(argv[0], 16, &oid)) {
    reply_err(E_ARGS, "rmeta");
    return;
  }

  optiga_lib_status_t rs = chip_ensure_open();
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "open");
    return;
  }

  uint8_t  meta[META_MAX];
  uint16_t length = sizeof(meta);

  bridge_status = OPTIGA_LIB_BUSY;
  rs = wait_busy(optiga_util_read_metadata(me_util, oid, meta, &length));
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "read");
    return;
  }

  reply_ok();
  print_hex(meta, length);
  Serial.println();
}

/*
 * WMETA <oid> <hex>
 *
 * The hex is a constructed TLV exactly as RMETA returns it, and it is sent
 * unexamined - the firmware stays a complete mapping of the API.
 *
 * Several of the things this can write are one-way. Advancing an object's LcsO
 * is irreversible, and because E0F1-E0F3 carry `change: lcso < operational`,
 * advancing theirs to operational makes them permanently immutable. Setting an
 * access condition to NEV (0xFF) locks that operation out for good. The chip
 * will do all of it without asking, so TrustM.write_metadata() is what refuses;
 * see bridge-plan.md section 3.5.
 */
static void cmd_wmeta(int argc, char **argv)
{
  if (argc != 2) {
    reply_err(E_ARGS, "wmeta");
    return;
  }

  uint16_t oid;
  if (!parse_u16(argv[0], 16, &oid)) {
    reply_err(E_ARGS, "wmeta");
    return;
  }

  uint8_t meta[META_MAX];
  int32_t length = parse_hex(argv[1], meta, sizeof(meta));
  if (HEX_TOO_LONG == length) {
    reply_err(E_RANGE, "wmeta");
    return;
  }
  if (length <= 0) {
    reply_err(E_ARGS, "wmeta");
    return;
  }

  optiga_lib_status_t rs = chip_ensure_open();
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "open");
    return;
  }

  bridge_status = OPTIGA_LIB_BUSY;
  rs = wait_busy(optiga_util_write_metadata(me_util, oid, meta,
                                            (uint8_t)length));
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "write");
    return;
  }

  reply_ok();
  Serial.println(length);
}

/* ------------------------------------------------------------------- keys */

/* A P-384 SubjectPublicKeyInfo is ~120 bytes and its DER signature ~104. The
 * exported private key is the awkward one: optiga_crypt_ecc_generate_keypair
 * takes no length for it and never reports how much it wrote, so the buffer is
 * sized for the largest thing the chip can produce and the length is recovered
 * from the DER afterwards. */
#define KEY_PUB_MAX       160
#define KEY_PRIV_MAX      128
#define SIG_MAX           160
#define DIGEST_MAX        64

/* Length of the DER object starting at `data`, header included, or 0 if that
 * is not a well-formed short- or long-form TLV inside `available`. Used only to
 * measure a buffer the library filled without saying how far. */
static uint16_t der_length(const uint8_t *data, uint16_t available)
{
  if (available < 2) {
    return 0;
  }

  uint8_t first = data[1];
  if (first < 0x80) {                       /* short form */
    uint16_t total = 2 + first;
    return (total <= available) ? total : 0;
  }

  uint8_t count = first & 0x7F;             /* long form: count length bytes */
  if (count == 0 || count > 2 || (uint16_t)(2 + count) > available) {
    return 0;
  }
  uint32_t length = 0;
  for (uint8_t i = 0; i < count; i++) {
    length = (length << 8) | data[2 + i];
  }
  uint32_t total = 2 + count + length;
  return (total <= available) ? (uint16_t)total : 0;
}

static bool parse_curve(const char *text, optiga_ecc_curve_t *out)
{
  if (!strcasecmp(text, "p256") || !strcasecmp(text, "nistp256") ||
      !strcasecmp(text, "nist_p_256")) {
    *out = OPTIGA_ECC_CURVE_NIST_P_256;
    return true;
  }
  if (!strcasecmp(text, "p384") || !strcasecmp(text, "nistp384") ||
      !strcasecmp(text, "nist_p_384")) {
    *out = OPTIGA_ECC_CURVE_NIST_P_384;
    return true;
  }
  return false;
}

/* Key usage is a bitmask, so "sign+auth" is a legitimate request rather than a
 * typo. strtok_r is safe here: dispatch finished tokenising before any command
 * ran. */
static bool parse_usage(const char *text, uint8_t *out)
{
  size_t length = strlen(text);
  char   buf[64];

  if (length == 0 || length >= sizeof(buf)) {
    return false;
  }
  /* strtok_r would quietly swallow "sign+", "+sign" and "sign++auth". They all
   * have an unambiguous meaning, but accepting them means a typo in a usage
   * list goes unmentioned, which is the same trade RAND makes over "32x". */
  if (text[0] == '+' || text[length - 1] == '+' || strstr(text, "++")) {
    return false;
  }
  strcpy(buf, text);

  uint8_t mask = 0;
  char *saveptr = NULL;
  for (char *tok = strtok_r(buf, "+", &saveptr);
       tok != NULL;
       tok = strtok_r(NULL, "+", &saveptr)) {
    if      (!strcasecmp(tok, "sign"))    mask |= OPTIGA_KEY_USAGE_SIGN;
    else if (!strcasecmp(tok, "auth"))    mask |= OPTIGA_KEY_USAGE_AUTHENTICATION;
    else if (!strcasecmp(tok, "agree"))   mask |= OPTIGA_KEY_USAGE_KEY_AGREEMENT;
    else if (!strcasecmp(tok, "encrypt")) mask |= OPTIGA_KEY_USAGE_ENCRYPTION;
    else return false;
  }
  if (mask == 0) {
    return false;
  }
  *out = mask;
  return true;
}

static bool parse_slot(const char *text, optiga_key_id_t *out)
{
  if (!strcasecmp(text, "session")) {
    *out = OPTIGA_KEY_ID_SESSION_BASED;
    return true;
  }
  uint16_t oid;
  if (!parse_u16(text, 16, &oid)) {
    return false;
  }
  *out = (optiga_key_id_t)oid;
  return true;
}

/*
 * KEYGEN <slot|session|export> [curve] [usage]
 *
 * Answers with the public key as DER SubjectPublicKeyInfo, and with the private
 * key after it when `export` was asked for.
 *
 * `export` occupies the slot position rather than being a trailing flag,
 * because the two are mutually exclusive in the API: export_private_key = TRUE
 * makes the `private_key` argument a buffer instead of an OID, so a key is
 * either kept in the chip or handed to the host, never both.
 *
 * As with WDATA there is no guard here on which slot is written. E0F0 holds the
 * factory attestation key; the chip's own metadata says `change: never` and
 * should refuse, but TrustM.generate_keypair() is what actually enforces it.
 */
static void cmd_keygen(int argc, char **argv)
{
  if (argc < 1 || argc > 3) {
    reply_err(E_ARGS, "keygen");
    return;
  }

  bool            export_private = !strcasecmp(argv[0], "export");
  optiga_key_id_t slot           = OPTIGA_KEY_ID_E0F1;

  if (!export_private && !parse_slot(argv[0], &slot)) {
    reply_err(E_ARGS, "keygen");
    return;
  }

  optiga_ecc_curve_t curve = OPTIGA_ECC_CURVE_NIST_P_256;
  uint8_t            usage = OPTIGA_KEY_USAGE_SIGN;

  if (argc >= 2 && !parse_curve(argv[1], &curve)) {
    reply_err(E_ARGS, "keygen");
    return;
  }
  if (argc >= 3 && !parse_usage(argv[2], &usage)) {
    reply_err(E_ARGS, "keygen");
    return;
  }

  optiga_lib_status_t rs = chip_ensure_open();
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "open");
    return;
  }

  uint8_t  pub[KEY_PUB_MAX];
  uint8_t  priv[KEY_PRIV_MAX];
  uint16_t pub_len = sizeof(pub);

  memset(priv, 0, sizeof(priv));

  bridge_status = OPTIGA_LIB_BUSY;
  rs = wait_busy(optiga_crypt_ecc_generate_keypair(
        me_crypt, curve, usage, export_private ? TRUE : FALSE,
        export_private ? (void *)priv : (void *)&slot,
        pub, &pub_len));
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "keygen");
    return;
  }

  reply_ok();
  print_hex(pub, pub_len);

  if (export_private) {
    uint16_t priv_len = der_length(priv, sizeof(priv));
    if (priv_len == 0) {
      /* The chip wrote something that is not a DER object, so there is no
       * honest way to say where it ends. Better to fail than to hand back a
       * guess with a private key in it. */
      reply_err(E_ARGS, "keygen-export");
      return;
    }
    Serial.print(' ');
    print_hex(priv, priv_len);
  }
  Serial.println();
}

/*
 * SIGN <slot|session> <digest-hex>
 *
 * The digest is signed as given - the chip does no hashing, so its length must
 * match the curve (32 bytes for P-256, 48 for P-384).
 *
 * What comes back is NOT a complete DER ECDSA signature. The chip emits the two
 * INTEGERs for r and s with no SEQUENCE wrapped around them, so it has to be
 * wrapped before any ordinary verifier will look at it. The host does that in
 * trustm/signature.py rather than the firmware doing it, so this command stays
 * a faithful report of what the chip produced.
 */
static void cmd_sign(int argc, char **argv)
{
  if (argc != 2) {
    reply_err(E_ARGS, "sign");
    return;
  }

  optiga_key_id_t slot;
  if (!parse_slot(argv[0], &slot)) {
    reply_err(E_ARGS, "sign");
    return;
  }

  uint8_t digest[DIGEST_MAX];
  int32_t digest_len = parse_hex(argv[1], digest, sizeof(digest));
  if (HEX_TOO_LONG == digest_len) {
    reply_err(E_RANGE, "sign");
    return;
  }
  if (digest_len <= 0) {
    reply_err(E_ARGS, "sign");
    return;
  }

  optiga_lib_status_t rs = chip_ensure_open();
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "open");
    return;
  }

  uint8_t  signature[SIG_MAX];
  uint16_t sig_len = sizeof(signature);

  bridge_status = OPTIGA_LIB_BUSY;
  rs = wait_busy(optiga_crypt_ecdsa_sign(me_crypt, digest, (uint8_t)digest_len,
                                         slot, signature, &sig_len));
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "sign");
    return;
  }

  reply_ok();
  print_hex(signature, sig_len);
  Serial.println();
}

/* ---------------------------------------------------- hashing and counters */

/* The Arduino wrapper uses 130 bytes for a SHA-256 context and the headers
 * define no constant for it, so this matches the only figure anyone has. */
#define HASH_CTX_LEN      130
#define SHA256_LEN        32

/* RSA is the reason these are not sized from the ECC numbers: a 2048-bit
 * signature is 256 bytes and its public key DER around 270. */
#define RSA_SIG_MAX       288
#define PUBKEY_MAX        320

/* A multi-part hash keeps its context between commands, so it is the one piece
 * of cross-command state in the firmware. One at a time, which is the same
 * invariant everything else here relies on. */
static uint8_t               hash_ctx_buf[HASH_CTX_LEN];
static optiga_hash_context_t hash_ctx;
static bool                  hash_active = false;

static void hash_context_init(void)
{
  hash_ctx.context_buffer        = hash_ctx_buf;
  hash_ctx.context_buffer_length = sizeof(hash_ctx_buf);
  hash_ctx.hash_algo             = (uint8_t)OPTIGA_HASH_TYPE_SHA_256;
}

/*
 * HASHSTART  /  HASHUPD <hex>  /  HASHFIN
 *
 * The streaming form, for data past what one line can carry. The chip holds the
 * hash context and the firmware holds the handle to it, so anything larger than
 * DATA_LEN_MAX is hashed as a sequence of updates.
 */
static void cmd_hashstart(int argc, char **argv)
{
  (void)argv;
  if (argc != 0) {
    reply_err(E_ARGS, "hashstart");
    return;
  }

  optiga_lib_status_t rs = chip_ensure_open();
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "open");
    return;
  }

  hash_context_init();
  bridge_status = OPTIGA_LIB_BUSY;
  rs = wait_busy(optiga_crypt_hash_start(me_crypt, &hash_ctx));
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "hash-start");
    return;
  }

  hash_active = true;
  reply_ok();
  Serial.println("started");
}

static void cmd_hashupd(int argc, char **argv)
{
  if (argc != 1) {
    reply_err(E_ARGS, "hashupd");
    return;
  }
  if (!hash_active) {
    reply_err(E_STATE, "hashupd");
    return;
  }

  int32_t length = parse_hex(argv[0], data_buf, DATA_LEN_MAX);
  if (HEX_TOO_LONG == length) {
    reply_err(E_RANGE, "hashupd");
    return;
  }
  if (length <= 0) {
    reply_err(E_ARGS, "hashupd");
    return;
  }

  hash_data_from_host_t input;
  input.buffer = data_buf;
  input.length = (uint32_t)length;

  bridge_status = OPTIGA_LIB_BUSY;
  optiga_lib_status_t rs = wait_busy(
      optiga_crypt_hash_update(me_crypt, &hash_ctx,
                               OPTIGA_CRYPT_HOST_DATA, &input));
  if (OPTIGA_LIB_SUCCESS != rs) {
    /* The context is no longer trustworthy after a failed update, and silently
     * carrying on would produce a digest of the wrong thing. */
    hash_active = false;
    reply_err(rs, "hash-update");
    return;
  }

  reply_ok();
  Serial.println(length);
}

static void cmd_hashfin(int argc, char **argv)
{
  (void)argv;
  if (argc != 0) {
    reply_err(E_ARGS, "hashfin");
    return;
  }
  if (!hash_active) {
    reply_err(E_STATE, "hashfin");
    return;
  }

  uint8_t digest[SHA256_LEN];
  bridge_status = OPTIGA_LIB_BUSY;
  optiga_lib_status_t rs = wait_busy(
      optiga_crypt_hash_finalize(me_crypt, &hash_ctx, digest));
  hash_active = false;
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "hash-finalize");
    return;
  }

  reply_ok();
  print_hex(digest, sizeof(digest));
  Serial.println();
}

/*
 * HASH <hex>
 *
 * SHA-256 on the chip rather than on the host. Not a shortcut - the desktop
 * hashes faster - but it is what feeds the chip's own digest-consuming
 * commands, and it makes the hash context observable.
 *
 * The library exposes no one-shot call, so this is start/update/finalize with
 * the context living on our stack. Only SHA-256 exists on V1.
 */
static void cmd_hash(int argc, char **argv)
{
  if (argc != 1) {
    reply_err(E_ARGS, "hash");
    return;
  }

  int32_t length = parse_hex(argv[0], data_buf, DATA_LEN_MAX);
  if (HEX_TOO_LONG == length) {
    reply_err(E_RANGE, "hash");
    return;
  }
  if (length <= 0) {
    reply_err(E_ARGS, "hash");
    return;
  }

  optiga_lib_status_t rs = chip_ensure_open();
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "open");
    return;
  }

  hash_data_from_host_t input;

  hash_context_init();
  hash_active = false;          /* a one-shot abandons any streaming context */

  bridge_status = OPTIGA_LIB_BUSY;
  rs = wait_busy(optiga_crypt_hash_start(me_crypt, &hash_ctx));
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "hash-start");
    return;
  }

  input.buffer = data_buf;
  input.length = (uint32_t)length;

  bridge_status = OPTIGA_LIB_BUSY;
  rs = wait_busy(optiga_crypt_hash_update(me_crypt, &hash_ctx,
                                          OPTIGA_CRYPT_HOST_DATA, &input));
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "hash-update");
    return;
  }

  uint8_t digest[SHA256_LEN];
  bridge_status = OPTIGA_LIB_BUSY;
  rs = wait_busy(optiga_crypt_hash_finalize(me_crypt, &hash_ctx, digest));
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "hash-finalize");
    return;
  }

  reply_ok();
  print_hex(digest, sizeof(digest));
  Serial.println();
}

/*
 * CTRINC <oid> [step]
 *
 * Increments a monotonic counter by `step` (default 1). A counter object holds
 * eight bytes - a four-byte value followed by a four-byte threshold - and the
 * chip refuses once the value would pass the threshold. Read it with RDATA;
 * set the threshold by writing all eight bytes with WDATA.
 *
 * "Monotonic" is about the counter, not the object: while the object's change
 * access condition is still open, WDATA can reset the value. It becomes truly
 * one-way once the object is locked.
 *
 * A step that would carry the value past the threshold saturates at it and
 * reports success. Only an increment attempted when the value is already at
 * the threshold fails, with 0x800E.
 */
static void cmd_ctrinc(int argc, char **argv)
{
  if (argc < 1 || argc > 2) {
    reply_err(E_ARGS, "ctrinc");
    return;
  }

  uint16_t oid;
  uint16_t step = 1;

  if (!parse_u16(argv[0], 16, &oid)) {
    reply_err(E_ARGS, "ctrinc");
    return;
  }
  if (argc == 2) {
    if (!parse_u16(argv[1], 10, &step)) {
      reply_err(E_ARGS, "ctrinc");
      return;
    }
    /* optiga_util_update_count takes a uint8_t, so anything larger is a
     * request the API cannot carry rather than one the chip would refuse. */
    if (step == 0 || step > 0xFF) {
      reply_err(E_RANGE, "ctrinc");
      return;
    }
  }

  optiga_lib_status_t rs = chip_ensure_open();
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "open");
    return;
  }

  bridge_status = OPTIGA_LIB_BUSY;
  rs = wait_busy(optiga_util_update_count(me_util, oid, (uint8_t)step));
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "count");
    return;
  }

  /* Deliberately no number here. An increment that would pass the threshold
   * SATURATES at it and still succeeds, so echoing the requested step would
   * claim a move the counter did not make. Read the counter to find out where
   * it landed - TrustM.increment_counter() does exactly that. */
  reply_ok();
  Serial.println();
}

/*
 * VERIFY <curve> <pubkey-hex> <digest-hex> <sig-hex>
 *
 * ECDSA verification on the chip, against a public key supplied by the host.
 * The signature is in the chip's own shape - r and s with no outer SEQUENCE -
 * because that is what SIGN produced and what this consumes.
 *
 * A failed verification is a device error, not an OK with a false in it: the
 * chip reports it through the same status path as everything else, so the
 * bridge does not invent a second convention for it.
 */
static void cmd_verify(int argc, char **argv)
{
  if (argc != 4) {
    reply_err(E_ARGS, "verify");
    return;
  }

  optiga_ecc_curve_t curve;
  if (!parse_curve(argv[0], &curve)) {
    reply_err(E_ARGS, "verify");
    return;
  }

  static uint8_t pubkey[PUBKEY_MAX];
  uint8_t        digest[DIGEST_MAX];
  uint8_t        signature[RSA_SIG_MAX];

  int32_t pub_len = parse_hex(argv[1], pubkey, sizeof(pubkey));
  int32_t dig_len = parse_hex(argv[2], digest, sizeof(digest));
  int32_t sig_len = parse_hex(argv[3], signature, sizeof(signature));

  if (HEX_TOO_LONG == pub_len || HEX_TOO_LONG == dig_len ||
      HEX_TOO_LONG == sig_len) {
    reply_err(E_RANGE, "verify");
    return;
  }
  if (pub_len <= 0 || dig_len <= 0 || sig_len <= 0) {
    reply_err(E_ARGS, "verify");
    return;
  }

  optiga_lib_status_t rs = chip_ensure_open();
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "open");
    return;
  }

  public_key_from_host_t peer;
  peer.public_key = pubkey;
  peer.length     = (uint16_t)pub_len;
  peer.key_type   = (uint8_t)curve;

  bridge_status = OPTIGA_LIB_BUSY;
  rs = wait_busy(optiga_crypt_ecdsa_verify(me_crypt, digest, (uint8_t)dig_len,
                                           signature, (uint16_t)sig_len,
                                           OPTIGA_CRYPT_HOST_DATA, &peer));
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "verify");
    return;
  }

  reply_ok();
  Serial.println("verified");
}

/*
 * ECDH <slot|session> <curve> <peer-pubkey-hex>
 *
 * Key agreement against a peer public key, with the shared secret exported to
 * the host. Exporting it is the only way to check the result against the
 * desktop, which is the point here; a real protocol would leave it in a session
 * object by passing FALSE and consume it with a key-derivation command.
 *
 * optiga_crypt_ecdh reports no output length, so the buffer is sized from the
 * curve - 32 bytes for P-256, 48 for P-384.
 */
static void cmd_ecdh(int argc, char **argv)
{
  if (argc != 3) {
    reply_err(E_ARGS, "ecdh");
    return;
  }

  optiga_key_id_t    slot;
  optiga_ecc_curve_t curve;

  if (!parse_slot(argv[0], &slot) || !parse_curve(argv[1], &curve)) {
    reply_err(E_ARGS, "ecdh");
    return;
  }

  static uint8_t pubkey[PUBKEY_MAX];
  int32_t pub_len = parse_hex(argv[2], pubkey, sizeof(pubkey));
  if (HEX_TOO_LONG == pub_len) {
    reply_err(E_RANGE, "ecdh");
    return;
  }
  if (pub_len <= 0) {
    reply_err(E_ARGS, "ecdh");
    return;
  }

  optiga_lib_status_t rs = chip_ensure_open();
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "open");
    return;
  }

  public_key_from_host_t peer;
  peer.public_key = pubkey;
  peer.length     = (uint16_t)pub_len;
  peer.key_type   = (uint8_t)curve;

  uint8_t  secret[64];
  uint16_t secret_len =
      (curve == OPTIGA_ECC_CURVE_NIST_P_384) ? 48 : 32;

  memset(secret, 0, sizeof(secret));

  bridge_status = OPTIGA_LIB_BUSY;
  rs = wait_busy(optiga_crypt_ecdh(me_crypt, slot, &peer, TRUE, secret));
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "ecdh");
    return;
  }

  reply_ok();
  print_hex(secret, secret_len);
  Serial.println();
}

/*
 * RSAGEN <slot> <1024|2048> [usage]
 * RSASIGN <slot> <digest-hex> [sha256|sha384]
 *
 * Whether these work at all depends on the silicon: RSA is an OPTIGA Trust M
 * SKU option, and the host library being built with it enabled says nothing
 * about the chip on the other end of the I2C bus. A chip without it answers
 * with a device error, which is the honest outcome to report.
 */
static void cmd_rsagen(int argc, char **argv)
{
  if (argc < 2 || argc > 3) {
    reply_err(E_ARGS, "rsagen");
    return;
  }

  optiga_key_id_t slot;
  if (!parse_slot(argv[0], &slot)) {
    reply_err(E_ARGS, "rsagen");
    return;
  }

  optiga_rsa_key_type_t key_type;
  if      (!strcmp(argv[1], "1024")) key_type = OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL;
  else if (!strcmp(argv[1], "2048")) key_type = OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL;
  else { reply_err(E_ARGS, "rsagen"); return; }

  uint8_t usage = OPTIGA_KEY_USAGE_SIGN;
  if (argc == 3 && !parse_usage(argv[2], &usage)) {
    reply_err(E_ARGS, "rsagen");
    return;
  }

  optiga_lib_status_t rs = chip_ensure_open();
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "open");
    return;
  }

  static uint8_t pubkey[PUBKEY_MAX];
  uint16_t       pub_len = sizeof(pubkey);

  bridge_status = OPTIGA_LIB_BUSY;
  rs = wait_busy(optiga_crypt_rsa_generate_keypair(
        me_crypt, key_type, usage, FALSE, &slot, pubkey, &pub_len));
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "rsagen");
    return;
  }

  reply_ok();
  print_hex(pubkey, pub_len);
  Serial.println();
}

static void cmd_rsasign(int argc, char **argv)
{
  if (argc < 2 || argc > 3) {
    reply_err(E_ARGS, "rsasign");
    return;
  }

  optiga_key_id_t slot;
  if (!parse_slot(argv[0], &slot)) {
    reply_err(E_ARGS, "rsasign");
    return;
  }

  uint8_t digest[DIGEST_MAX];
  int32_t dig_len = parse_hex(argv[1], digest, sizeof(digest));
  if (HEX_TOO_LONG == dig_len) {
    reply_err(E_RANGE, "rsasign");
    return;
  }
  if (dig_len <= 0) {
    reply_err(E_ARGS, "rsasign");
    return;
  }

  optiga_rsa_signature_scheme_t scheme = OPTIGA_RSASSA_PKCS1_V15_SHA256;
  if (argc == 3) {
    if      (!strcasecmp(argv[2], "sha256")) scheme = OPTIGA_RSASSA_PKCS1_V15_SHA256;
    else if (!strcasecmp(argv[2], "sha384")) scheme = OPTIGA_RSASSA_PKCS1_V15_SHA384;
    else { reply_err(E_ARGS, "rsasign"); return; }
  }

  optiga_lib_status_t rs = chip_ensure_open();
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "open");
    return;
  }

  static uint8_t signature[RSA_SIG_MAX];
  uint16_t       sig_len = sizeof(signature);

  bridge_status = OPTIGA_LIB_BUSY;
  rs = wait_busy(optiga_crypt_rsa_sign(me_crypt, scheme, digest,
                                       (uint8_t)dig_len, slot,
                                       signature, &sig_len, 0));
  if (OPTIGA_LIB_SUCCESS != rs) {
    reply_err(rs, "rsasign");
    return;
  }

  reply_ok();
  print_hex(signature, sig_len);
  Serial.println();
}

/* -------------------------------------------------------------- dispatch */

/*
 * Splits an optional leading tag off `text`, pointing cur_tag at it and
 * returning what remains. A tag is any first token starting with a digit;
 * command names are alphabetic (or '?'), so nothing can be read as both.
 */
static char *take_tag(char *text)
{
  cur_tag = "-";

  while (*text == ' ' || *text == '\t') {
    text++;
  }
  if (!isdigit((unsigned char)*text)) {
    return text;
  }

  char *end = text;
  while (*end && *end != ' ' && *end != '\t') {
    end++;
  }
  if (end - text > TAG_MAX) {
    return text;      /* too long to echo; treated as an unknown command */
  }

  bool more = (*end != '\0');
  *end = '\0';
  cur_tag = text;
  return more ? end + 1 : end;
}

static void dispatch(char *text)
{
  char *argv[MAX_ARGS];
  int   argc = 0;

  char *saveptr = NULL;
  for (char *tok = strtok_r(text, " \t", &saveptr);
       tok != NULL && argc < MAX_ARGS;
       tok = strtok_r(NULL, " \t", &saveptr)) {
    argv[argc++] = tok;
  }

  if (argc < 1) {
    /* A bare tag, or a line of nothing but spaces. The tag is still echoed, so
     * a host waiting on it gets an answer rather than a timeout. */
    if (cur_tag[0] != '-') {
      reply_err(E_ARGS, "command");
    }
    return;
  }

  char *cmd = argv[0];
  for (char *c = cmd; *c; c++) {
    *c = toupper((unsigned char)*c);
  }

  int    rest = argc - 1;
  char **args = &argv[1];

  /* cur_cmd is the canonical name, not what was typed: TRNG and DRNG answer as
   * RAND and '?' answers as HELP, so a host matching replies against what it
   * sent needs no table of aliases. */
  if      (!strcmp(cmd, "PING"))  { cur_cmd = "PING";  cmd_ping(); }
  else if (!strcmp(cmd, "UID"))   { cur_cmd = "UID";   cmd_uid(); }
  else if (!strcmp(cmd, "RAND"))  { cur_cmd = "RAND";  cmd_rand(rest, args, OPTIGA_RNG_TYPE_TRNG, false); }
  else if (!strcmp(cmd, "TRNG"))  { cur_cmd = "RAND";  cmd_rand(rest, args, OPTIGA_RNG_TYPE_TRNG, true); }
  else if (!strcmp(cmd, "DRNG"))  { cur_cmd = "RAND";  cmd_rand(rest, args, OPTIGA_RNG_TYPE_DRNG, true); }
  else if (!strcmp(cmd, "RDATA")) { cur_cmd = "RDATA"; cmd_rdata(rest, args); }
  else if (!strcmp(cmd, "WDATA")) { cur_cmd = "WDATA"; cmd_wdata(rest, args); }
  else if (!strcmp(cmd, "RMETA")) { cur_cmd = "RMETA"; cmd_rmeta(rest, args); }
  else if (!strcmp(cmd, "WMETA")) { cur_cmd = "WMETA"; cmd_wmeta(rest, args); }
  else if (!strcmp(cmd, "KEYGEN")){ cur_cmd = "KEYGEN"; cmd_keygen(rest, args); }
  else if (!strcmp(cmd, "SIGN"))  { cur_cmd = "SIGN";  cmd_sign(rest, args); }
  else if (!strcmp(cmd, "VERIFY")){ cur_cmd = "VERIFY"; cmd_verify(rest, args); }
  else if (!strcmp(cmd, "HASH"))  { cur_cmd = "HASH";  cmd_hash(rest, args); }
  else if (!strcmp(cmd, "HASHSTART")) { cur_cmd = "HASHSTART"; cmd_hashstart(rest, args); }
  else if (!strcmp(cmd, "HASHUPD"))   { cur_cmd = "HASHUPD"; cmd_hashupd(rest, args); }
  else if (!strcmp(cmd, "HASHFIN"))   { cur_cmd = "HASHFIN"; cmd_hashfin(rest, args); }
  else if (!strcmp(cmd, "ECDH"))  { cur_cmd = "ECDH";  cmd_ecdh(rest, args); }
  else if (!strcmp(cmd, "CTRINC")){ cur_cmd = "CTRINC"; cmd_ctrinc(rest, args); }
  else if (!strcmp(cmd, "RSAGEN")){ cur_cmd = "RSAGEN"; cmd_rsagen(rest, args); }
  else if (!strcmp(cmd, "RSASIGN")){ cur_cmd = "RSASIGN"; cmd_rsasign(rest, args); }
  else if (!strcmp(cmd, "HELP") ||
           !strcmp(cmd, "?"))     { cur_cmd = "HELP";  cmd_help(); }
  else {
    /* The offending token is whatever arrived - possibly a kilobyte of line
     * noise - so it goes back capped rather than whole. */
    char seen[TAG_MAX + 1];
    snprintf(seen, sizeof(seen), "%s", cmd);
    cur_cmd = "-";
    reply_err(E_CMD, seen);
  }
}

/* ------------------------------------------------------------ line reader */

static char     line[MAX_LINE + 1];
static uint16_t line_len = 0;
static bool     line_overflow = false;

static void handle_line(void)
{
  char *text = line;

  /* Both the '>' and the space after it are optional, so ">RAND 32",
   * "> RAND 32" and "RAND 32" are the same command. The host library still
   * sends the '>' - it costs nothing and marks intent in a raw capture. */
  if (*text == '>') {
    text++;
  }

  cur_cmd = "-";
  text = take_tag(text);

  if (line_overflow) {
    /* The tag is the first token, so it survived the truncation; recovering it
     * lets the host match the error to the request that caused it. */
    reply_err(E_OVERFLOW, "line");
    return;
  }
  dispatch(text);
}

void setup()
{
  Serial.begin(115200);
}

void loop()
{
  while (Serial.available()) {
    char c = (char)Serial.read();

    if (c == '\n' || c == '\r') {
      if (line_len > 0 || line_overflow) {
        line[line_len] = '\0';
        handle_line();
      }
      line_len = 0;
      line_overflow = false;
      continue;
    }

    if (line_len >= MAX_LINE) {
      line_overflow = true;   /* keep consuming until the newline */
      continue;
    }
    line[line_len++] = c;
  }
}
