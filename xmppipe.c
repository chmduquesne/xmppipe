/*
 * xmppipe
 * transmit raw data though an xmpp tunnel
 *
 * Copyright (C) 2011 Christophe-Marie Duquesne
 *
 * This software is provided AS-IS with no warranty, either express
 * or implied.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <stdarg.h>

/* for to_base64 encoding */
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <strophe.h>

#ifndef DEFAULT_TIMEOUT
#define DEFAULT_TIMEOUT 1
#endif

/* user must free the result */
char *to_base64(const unsigned char *input, int length)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = (char *)malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length-1);
    buff[bptr->length-1] = 0;

    BIO_free_all(b64);

    return buff;
}

/* user must free the result */
char *from_base64(unsigned char *input, int length)
{
    BIO *b64, *bmem;

    char *buffer = (char *)malloc(length);
    memset(buffer, 0, length);

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);

    BIO_read(bmem, buffer, length);

    BIO_free_all(bmem);

    return buffer;
}

/* exits the program printing an error */
void
eprintf(const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(EXIT_FAILURE);
}

int version_handler(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza, void * const userdata)
{
    xmpp_stanza_t *reply, *query, *name, *version, *text;
    char *ns;
    xmpp_ctx_t *ctx = (xmpp_ctx_t*)userdata;
    printf("Received version request from %s\n", xmpp_stanza_get_attribute(stanza, "from"));

    reply = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(reply, "iq");
    xmpp_stanza_set_type(reply, "result");
    xmpp_stanza_set_id(reply, xmpp_stanza_get_id(stanza));
    xmpp_stanza_set_attribute(reply, "to", xmpp_stanza_get_attribute(stanza, "from"));

    query = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(query, "query");
    ns = xmpp_stanza_get_ns(xmpp_stanza_get_children(stanza));
    if (ns) {
        xmpp_stanza_set_ns(query, ns);
    }

    name = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(name, "name");
    xmpp_stanza_add_child(query, name);

    text = xmpp_stanza_new(ctx);
    xmpp_stanza_set_text(text, "xmppipe");
    xmpp_stanza_add_child(name, text);

    version = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(version, "version");
    xmpp_stanza_add_child(query, version);

    text = xmpp_stanza_new(ctx);
    xmpp_stanza_set_text(text, "1.0");
    xmpp_stanza_add_child(version, text);

    xmpp_stanza_add_child(reply, query);

    xmpp_send(conn, reply);
    xmpp_stanza_release(reply);
    return 1;
}


int message_handler(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza, void * const userdata)
{
    char *intext, *decoded_intext;
    if(!xmpp_stanza_get_child_by_name(stanza, "body")) return 1;
    if(!strcmp(xmpp_stanza_get_attribute(stanza, "type"), "error")) return 1;
    intext = xmpp_stanza_get_text(xmpp_stanza_get_child_by_name(stanza, "body"));

    decoded_intext = from_base64(intext, strlen(intext));
    fwrite((const void*)decoded_intext, 1, strlen(intext), stdout);
    free(decoded_intext);
    return 1;
}

/* define a handler for connection events */
void conn_handler(xmpp_conn_t * const conn, const xmpp_conn_event_t status,
          const int error, xmpp_stream_error_t * const stream_error,
          void * const userdata)
{
    xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;

    if (status == XMPP_CONN_CONNECT) {
        xmpp_stanza_t* pres;
        xmpp_handler_add(conn,version_handler, "jabber:iq:version", "iq", NULL, ctx);
        xmpp_handler_add(conn,message_handler, NULL, "message", NULL, ctx);

        /* Send initial <presence/> so that we appear online to contacts */
        pres = xmpp_stanza_new(ctx);
        xmpp_stanza_set_name(pres, "presence");
        xmpp_send(conn, pres);
        xmpp_stanza_release(pres);
    }
    else {
        xmpp_stop(ctx);
    }
}

void send_stdin_once(xmpp_conn_t * const conn, xmpp_ctx_t *ctx, char *jid_to)
{
    int n;
    char buf[1024], *stdin_b64;
    xmpp_stanza_t *message, *body, *text;

    while (n = fread(buf, sizeof(char), sizeof buf, stdin)){
        stdin_b64 = to_base64(buf, n);

        message = xmpp_stanza_new(ctx);
        xmpp_stanza_set_name(message, "message");
        xmpp_stanza_set_type(message, "chat");
        xmpp_stanza_set_attribute(message, "to", jid_to);

        body = xmpp_stanza_new(ctx);
        xmpp_stanza_set_name(body, "body");

        text = xmpp_stanza_new(ctx);
        xmpp_stanza_set_text(text, stdin_b64);
        xmpp_stanza_add_child(body, text);
        xmpp_stanza_add_child(message, body);

        xmpp_send(conn, message);
        xmpp_stanza_release(message);
        free(stdin_b64);
    }
}

void main_loop(xmpp_conn_t * const conn, xmpp_ctx_t *ctx, char *jid_to)
{
    /* enter the event loop -
       our connect handler will trigger an exit */
    while (1) {
        xmpp_run_once(ctx, DEFAULT_TIMEOUT);
        send_stdin_once(conn, ctx, jid_to);
    }
}

int main(int argc, char **argv)
{
    int flags;
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    xmpp_log_t *log;
    char *jid_from, *pass, *jid_to;

    if (argc != 4) {
    fprintf(stderr, "Usage: xmppipe <jid_from> <pass_from> <jid_to>\n\n");
    return 1;
    }

    jid_from = argv[1];
    pass = argv[2];
    jid_to = argv[3];

    /* init library */
    xmpp_initialize();

    /* create a context */
    ctx = xmpp_ctx_new(NULL, NULL);

    /* create a connection */
    conn = xmpp_conn_new(ctx);

    /* setup authentication information */
    xmpp_conn_set_jid(conn, jid_from);
    xmpp_conn_set_pass(conn, pass);

    /* initiate connection */
    xmpp_connect_client(conn, NULL, 0, conn_handler, ctx);

    /* set stdin to be non blocking */
    flags = fcntl(STDIN_FILENO, F_GETFL);
    flags |= O_NONBLOCK;
    fcntl(STDIN_FILENO, F_SETFL, flags);

    main_loop(conn, ctx, jid_to);

    /* release our connection and context */
    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);

    /* final shutdown of the library */
    xmpp_shutdown();

    return 0;
}
