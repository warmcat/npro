/*
 * c-heads: what C lws' h1 parser, lws_parse(), makes of heads, and its
 * dechunker, lws_http_dechunk_framing(), of chunked bodies
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Not part of npro's build: scripts/sync-c-h1.sh compiles it against a C
 * lws checkout's private headers and static library, runs it, and keeps
 * what it prints in c-heads.txt beside it, which npro-test's h1_c test
 * holds npro's parser to.
 *
 *   c-heads [--max <bytes>] [--limit <token index>=<bytes>]... [--fallback]
 *           [--mutations <n>] [--config <name>] <side>:<file>...
 *
 * Each file is a head, a request for side "server" or a response for side
 * "client", or for side "chunked" a chunked body, given to a fresh
 * connection's ah or dechunker in one piece, followed by <n>
 * variations of it: a few bytes changed, inserted, deleted, repeated or cut
 * off, chosen by xoshiro256** seeded from the file's name, so every run
 * makes the same ones.
 * A client's ah holds its own request first, as a real one's does.
 *
 * One line per head:
 *
 *   <config> <side> <name> <head, hex> <verdict>
 *
 * where the verdict is "complete <consumed> <table>", "more <table>",
 * "refused <status>" (a server's answer; a client's is "refused 0"),
 * "fail", "toolarge" or "fallback", and the table is "used=<ah->pos>",
 * then " t<token>=<fragment hex>,<fragment hex>..." for each token present,
 * in token order, then " u<name hex>=<value hex>" for each unknown header.
 * A chunked body's verdict is "end <consumed> <data hex>", "more <data
 * hex>" or "fail", the data being the chunks' payload, taken as C's callers
 * take it.  A head, or data, of no bytes is "-".
 */

#include "private-lib-core.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_HEAD 65536

static uint64_t xs[4];

static uint64_t
splitmix64(uint64_t *x)
{
	uint64_t z = (*x += 0x9e3779b97f4a7c15ull);

	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;

	return z ^ (z >> 31);
}

static uint64_t
rotl(uint64_t x, int k)
{
	return (x << k) | (x >> (64 - k));
}

static uint64_t
xoshiro(void)
{
	uint64_t r = rotl(xs[1] * 5, 7) * 9, t = xs[1] << 17;

	xs[2] ^= xs[0];
	xs[3] ^= xs[1];
	xs[1] ^= xs[2];
	xs[0] ^= xs[3];
	xs[2] ^= t;
	xs[3] = rotl(xs[3], 45);

	return r;
}

static size_t
below(size_t n)
{
	return n ? (size_t)(xoshiro() % n) : 0;
}

/* the bytes a head's parser treats specially, and some it does not */
static const char alphabet[] = "\r\n :%/.?&=+;\t\x7f\x80-_#aAzZ09Hh";

static uint8_t
some_byte(void)
{
	if (!below(8))
		return (uint8_t)xoshiro();

	return (uint8_t)alphabet[below(sizeof(alphabet) - 1)];
}

/* change the head in buf, *len long, in one to three ways */
static void
mutate(uint8_t *buf, size_t *len)
{
	int ops = 1 + (int)below(3);

	while (ops--) {
		size_t at = below(*len + 1), n;

		switch (below(5)) {
		case 0: /* change a byte */
			if (at < *len)
				buf[at] = some_byte();
			break;
		case 1: /* insert one */
			if (*len < MAX_HEAD) {
				memmove(buf + at + 1, buf + at, *len - at);
				buf[at] = some_byte();
				(*len)++;
			}
			break;
		case 2: /* delete one */
			if (at < *len) {
				memmove(buf + at, buf + at + 1, *len - at - 1);
				(*len)--;
			}
			break;
		case 3: /* repeat up to 16 of them */
			n = 1 + below(16);
			if (at + n <= *len && *len + n <= MAX_HEAD) {
				memmove(buf + at + n, buf + at, *len - at);
				(*len) += n;
			}
			break;
		default: /* cut it off */
			*len = at;
			break;
		}
	}
}

static void
hex(const uint8_t *p, size_t len)
{
	while (len--)
		printf("%02x", *p++);
}

/* bytes that are a field of the line of their own: "-" if there are none */
static void
hex_field(const uint8_t *p, size_t len)
{
	if (!len)
		printf("-");
	hex(p, len);
}

static void
dump_table(struct allocated_headers *ah)
{
	ah_data_idx_t ll;
	int n, f;

	printf("used=%u", (unsigned int)ah->pos);

	for (n = 0; n < WSI_TOKEN_COUNT; n++) {
		f = ah->frag_index[n];
		if (!f)
			continue;
		printf(" t%d=", n);
		do {
			hex((uint8_t *)ah->data + ah->frags[f].offset,
			    ah->frags[f].len);
			f = lws_ah_frag_next(ah, f);
			if (f)
				printf(",");
		} while (f);
	}

	for (ll = ah->unk_ll_head; ll;
	     ll = lws_ser_ru32be((uint8_t *)&ah->data[ll + UHO_LL])) {
		int nl = lws_ser_ru16be((uint8_t *)&ah->data[ll + UHO_NLEN]),
		    vl = lws_ser_ru16be((uint8_t *)&ah->data[ll + UHO_VLEN]);

		printf(" u");
		hex((uint8_t *)ah->data + ll + UHO_NAME, (size_t)nl);
		printf("=");
		hex((uint8_t *)ah->data + ll + UHO_NAME + nl, (size_t)vl);
	}
}

/* the status a refusing server wrote to its peer, or 0 */
static int
status_written(int fd)
{
	char buf[64];
	ssize_t n = read(fd, buf, sizeof(buf) - 1);

	if (n < 13 || strncmp(buf, "HTTP/1.", 7))
		return 0;
	buf[12] = '\0';

	return atoi(buf + 9);
}

/* a chunked body, given to the dechunker as C's h1 server and client do */
static void
dechunk(struct lws *wsi, uint8_t *body, size_t len)
{
	static uint8_t data[MAX_HEAD];
	size_t left = len, n, got = 0;
	uint8_t *p = body;
	int r;

	wsi->http.chunk_parser = ELCP_HEX;
	wsi->http.chunk_remaining = 0;
	wsi->http.chunk_skip = 0;

	while (left) {
		r = lws_http_dechunk_framing(wsi, &p, &left);
		if (r < 0) {
			printf("fail");
			return;
		}
		if (r == 1) {
			printf("end %d ", (int)(p - body));
			hex_field(data, got);
			return;
		}
		if (wsi->http.chunk_parser != ELCP_CONTENT || !left)
			continue;
		/* the payload, as much of this chunk as there is */
		n = (size_t)wsi->http.chunk_remaining;
		if (n > left)
			n = left;
		memcpy(data + got, p, n);
		got += n;
		p += n;
		left -= n;
		wsi->http.chunk_remaining -= (int)n;
		if (!wsi->http.chunk_remaining)
			wsi->http.chunk_parser = ELCP_POST_CR;
	}

	printf("more ");
	hex_field(data, got);
}

static int
one(struct lws_vhost *vh, const char *config, const char *side,
    const char *name, const uint8_t *head, size_t len)
{
	int client = !strcmp(side, "client"), sv[2], left, r;
	uint8_t buf[MAX_HEAD];
	struct lws *wsi;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv))
		return 1;
	fcntl(sv[1], F_SETFL, O_NONBLOCK);

	wsi = lws_adopt_socket_vhost(vh, sv[0]);
	if (!wsi) {
		fprintf(stderr, "adopt failed\n");
		return 1;
	}
	if (!wsi->stream.ah && lws_header_table_attach(wsi, 0)) {
		fprintf(stderr, "no ah\n");
		return 1;
	}
	if (!wsi->stream.ah) {
		fprintf(stderr, "no ah after attach\n");
		return 1;
	}

	if (client) {
		/* lws_parse() asks only which side it is on */
		wsi->wsistate = (wsi->wsistate & ~(lws_wsi_state_t)LWSIFR_SERVER) |
				LWSIFR_CLIENT;
		/* a client's ah holds its own request first */
		if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_PEER_ADDRESS,
					  "sansio") ||
		    lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_URI, "/x") ||
		    lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_HOST,
					  "sansio") ||
		    lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_METHOD, "GET")) {
			fprintf(stderr, "client tokens\n");
			return 1;
		}
	}

	printf("%s %s %s ", config, side, name);
	hex_field(head, len);
	printf(" ");

	memcpy(buf, head, len);
	if (!strcmp(side, "chunked")) {
		dechunk(wsi, buf, len);
		goto done;
	}

	left = (int)len;
	r = len ? (int)lws_parse(wsi, buf, &left) : LPR_OK;

	switch (r) {
	case LPR_OK:
		if (wsi->stream.ah->parser_state == WSI_PARSING_COMPLETE)
			printf("complete %d ", (int)len - left);
		else
			printf("more ");
		dump_table(wsi->stream.ah);
		break;
	case LPR_FAIL:
		printf("fail");
		break;
	case LPR_REFUSED:
		printf("refused %d", client ? 0 : status_written(sv[1]));
		break;
	case LPR_TOO_LARGE:
		printf("toolarge");
		break;
	case LPR_DO_FALLBACK:
		printf("fallback");
		break;
	default:
		printf("unknown %d", r);
		break;
	}
done:
	printf("\n");

	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "c-heads");
	close(sv[1]);

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

int
main(int argc, const char **argv)
{
	struct lws_token_limits limits;
	struct lws_context_creation_info info;
	const char *config = "default";
	static uint8_t head[MAX_HEAD], var[MAX_HEAD];
	int mutations = 0, have_limits = 0, n, m;
	uint64_t seed;
	struct lws_context *cx;
	struct lws_vhost *vh;

	lws_set_log_level(0, NULL);
	memset(&info, 0, sizeof(info));
	memset(&limits, 0, sizeof(limits));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	for (n = 1; n < argc && !strncmp(argv[n], "--", 2); n++) {
		if (!strcmp(argv[n], "--fallback")) {
			info.options |=
			   LWS_SERVER_OPTION_FALLBACK_TO_APPLY_LISTEN_ACCEPT_CONFIG;
			continue;
		}
		if (n + 1 == argc)
			goto usage;
		if (!strcmp(argv[n], "--max"))
			info.max_http_header_data =
					(unsigned short)atoi(argv[++n]);
		else if (!strcmp(argv[n], "--limit")) {
			const char *eq = strchr(argv[++n], '=');
			int t = atoi(argv[n]);

			if (!eq || t < 0 || t >= WSI_TOKEN_COUNT)
				goto usage;
			limits.token_limit[t] = (unsigned short)atoi(eq + 1);
			have_limits = 1;
		} else if (!strcmp(argv[n], "--mutations"))
			mutations = atoi(argv[++n]);
		else if (!strcmp(argv[n], "--config"))
			config = argv[++n];
		else
			goto usage;
	}
	if (have_limits)
		info.token_limits = &limits;

	cx = lws_create_context(&info);
	if (!cx)
		return 1;
	vh = lws_create_vhost(cx, &info);
	if (!vh)
		return 1;

	for (; n < argc; n++) {
		const char *colon = strchr(argv[n], ':'), *base;
		char side[8];
		size_t len, vlen;
		FILE *f;

		if (!colon || (size_t)(colon - argv[n]) >= sizeof(side))
			goto usage;
		memcpy(side, argv[n], (size_t)(colon - argv[n]));
		side[colon - argv[n]] = '\0';

		f = fopen(colon + 1, "rb");
		if (!f) {
			fprintf(stderr, "%s: can't open\n", colon + 1);
			return 1;
		}
		len = fread(head, 1, sizeof(head), f);
		fclose(f);

		base = strrchr(colon + 1, '/');
		base = base ? base + 1 : colon + 1;

		/*
		 * each head's variations are its own, from its name, whatever
		 * else is run with it
		 */
		seed = 0xcbf29ce484222325ull;
		for (m = 0; base[m]; m++)
			seed = (seed ^ (uint8_t)base[m]) * 0x100000001b3ull;
		for (m = 0; m < 4; m++)
			xs[m] = splitmix64(&seed);

		if (one(vh, config, side, base, head, len))
			return 1;
		for (m = 0; m < mutations; m++) {
			char name[300];

			memcpy(var, head, len);
			vlen = len;
			mutate(var, &vlen);
			lws_snprintf(name, sizeof(name), "%s~%d", base, m);
			if (one(vh, config, side, name, var, vlen))
				return 1;
		}
	}

	lws_context_destroy(cx);

	return 0;

usage:
	fprintf(stderr, "usage: c-heads [--max <bytes>] [--limit <token>=<n>]... "
			"[--fallback] [--mutations <n>] [--config <name>] "
			"<side>:<file>...\n");

	return 1;
}
