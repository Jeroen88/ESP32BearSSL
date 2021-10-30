#include "WiFi.h"
 
const char* ssid = "<YOUR SSID>";
const char* password =  "<YOUR PASSWORD>";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
//#include <arpa/inet.h>
#include <lwip/inet.h>
#include <unistd.h>

#include <bearssl.h>

/*
 * Connect to the specified host and port. The connected socket is
 * returned, or -1 on error.
 */
static int
host_connect(const char *host, const char *port)
{
  struct addrinfo hints, *si, *p;
  int fd;
  int err;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  err = getaddrinfo(host, port, &hints, &si);
  if (err != 0) {
    fprintf(stderr, "ERROR: getaddrinfo(): %s\n",
      strerror(err));
    return -1;
  }
  fd = -1;
  for (p = si; p != NULL; p = p->ai_next) {
    struct sockaddr *sa;
    void *addr;
    char tmp[INET6_ADDRSTRLEN + 50];

    sa = (struct sockaddr *)p->ai_addr;
    if (sa->sa_family == AF_INET) {
      addr = &((struct sockaddr_in *)sa)->sin_addr;
    } else if (sa->sa_family == AF_INET6) {
      addr = &((struct sockaddr_in6 *)sa)->sin6_addr;
    } else {
      addr = NULL;
    }
    if (addr != NULL) {
      inet_ntop(p->ai_family, addr, tmp, sizeof tmp);
    } else {
      sprintf(tmp, "<unknown family: %d>",
        (int)sa->sa_family);
    }
    fprintf(stderr, "connecting to: %s\n", tmp);
    fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0) {
      perror("socket()");
      continue;
    }
    if (connect(fd, p->ai_addr, p->ai_addrlen) < 0) {
      perror("connect()");
      close(fd);
      continue;
    }
    break;
  }
  if (p == NULL) {
    freeaddrinfo(si);
    fprintf(stderr, "ERROR: failed to connect\n");
    return -1;
  }
  freeaddrinfo(si);
  fprintf(stderr, "connected.\n");
  return fd;
}

/*
 * Low-level data read callback for the simplified SSL I/O API.
 */
static int
sock_read(void *ctx, unsigned char *buf, size_t len)
{
  for (;;) {
    ssize_t rlen;

    rlen = read(*(int *)ctx, buf, len);
    if (rlen <= 0) {
      if (rlen < 0 && errno == EINTR) {
        continue;
      }
      return -1;
    }
    return (int)rlen;
  }
}

/*
 * Low-level data write callback for the simplified SSL I/O API.
 */
static int
sock_write(void *ctx, const unsigned char *buf, size_t len)
{
  for (;;) {
    ssize_t wlen;

    wlen = write(*(int *)ctx, buf, len);
    if (wlen <= 0) {
      if (wlen < 0 && errno == EINTR) {
        continue;
      }
      return -1;
    }
    return (int)wlen;
  }
}

/*
 * The hardcoded trust anchors. These are the DN + public key that
 * correspond to the certificate google-com.pem.
 *
 * C code for hardcoded trust anchors can be generated with the "brssl"
 * command-line tool (with the "ta" command).
 */

static const unsigned char TA0_DN[] = {
	0x30, 0x47, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
	0x02, 0x55, 0x53, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0A,
	0x13, 0x19, 0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x20, 0x54, 0x72, 0x75,
	0x73, 0x74, 0x20, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x20,
	0x4C, 0x4C, 0x43, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03,
	0x13, 0x0B, 0x47, 0x54, 0x53, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x52,
	0x31
};

static const unsigned char TA0_RSA_N[] = {
	0xB6, 0x11, 0x02, 0x8B, 0x1E, 0xE3, 0xA1, 0x77, 0x9B, 0x3B, 0xDC, 0xBF,
	0x94, 0x3E, 0xB7, 0x95, 0xA7, 0x40, 0x3C, 0xA1, 0xFD, 0x82, 0xF9, 0x7D,
	0x32, 0x06, 0x82, 0x71, 0xF6, 0xF6, 0x8C, 0x7F, 0xFB, 0xE8, 0xDB, 0xBC,
	0x6A, 0x2E, 0x97, 0x97, 0xA3, 0x8C, 0x4B, 0xF9, 0x2B, 0xF6, 0xB1, 0xF9,
	0xCE, 0x84, 0x1D, 0xB1, 0xF9, 0xC5, 0x97, 0xDE, 0xEF, 0xB9, 0xF2, 0xA3,
	0xE9, 0xBC, 0x12, 0x89, 0x5E, 0xA7, 0xAA, 0x52, 0xAB, 0xF8, 0x23, 0x27,
	0xCB, 0xA4, 0xB1, 0x9C, 0x63, 0xDB, 0xD7, 0x99, 0x7E, 0xF0, 0x0A, 0x5E,
	0xEB, 0x68, 0xA6, 0xF4, 0xC6, 0x5A, 0x47, 0x0D, 0x4D, 0x10, 0x33, 0xE3,
	0x4E, 0xB1, 0x13, 0xA3, 0xC8, 0x18, 0x6C, 0x4B, 0xEC, 0xFC, 0x09, 0x90,
	0xDF, 0x9D, 0x64, 0x29, 0x25, 0x23, 0x07, 0xA1, 0xB4, 0xD2, 0x3D, 0x2E,
	0x60, 0xE0, 0xCF, 0xD2, 0x09, 0x87, 0xBB, 0xCD, 0x48, 0xF0, 0x4D, 0xC2,
	0xC2, 0x7A, 0x88, 0x8A, 0xBB, 0xBA, 0xCF, 0x59, 0x19, 0xD6, 0xAF, 0x8F,
	0xB0, 0x07, 0xB0, 0x9E, 0x31, 0xF1, 0x82, 0xC1, 0xC0, 0xDF, 0x2E, 0xA6,
	0x6D, 0x6C, 0x19, 0x0E, 0xB5, 0xD8, 0x7E, 0x26, 0x1A, 0x45, 0x03, 0x3D,
	0xB0, 0x79, 0xA4, 0x94, 0x28, 0xAD, 0x0F, 0x7F, 0x26, 0xE5, 0xA8, 0x08,
	0xFE, 0x96, 0xE8, 0x3C, 0x68, 0x94, 0x53, 0xEE, 0x83, 0x3A, 0x88, 0x2B,
	0x15, 0x96, 0x09, 0xB2, 0xE0, 0x7A, 0x8C, 0x2E, 0x75, 0xD6, 0x9C, 0xEB,
	0xA7, 0x56, 0x64, 0x8F, 0x96, 0x4F, 0x68, 0xAE, 0x3D, 0x97, 0xC2, 0x84,
	0x8F, 0xC0, 0xBC, 0x40, 0xC0, 0x0B, 0x5C, 0xBD, 0xF6, 0x87, 0xB3, 0x35,
	0x6C, 0xAC, 0x18, 0x50, 0x7F, 0x84, 0xE0, 0x4C, 0xCD, 0x92, 0xD3, 0x20,
	0xE9, 0x33, 0xBC, 0x52, 0x99, 0xAF, 0x32, 0xB5, 0x29, 0xB3, 0x25, 0x2A,
	0xB4, 0x48, 0xF9, 0x72, 0xE1, 0xCA, 0x64, 0xF7, 0xE6, 0x82, 0x10, 0x8D,
	0xE8, 0x9D, 0xC2, 0x8A, 0x88, 0xFA, 0x38, 0x66, 0x8A, 0xFC, 0x63, 0xF9,
	0x01, 0xF9, 0x78, 0xFD, 0x7B, 0x5C, 0x77, 0xFA, 0x76, 0x87, 0xFA, 0xEC,
	0xDF, 0xB1, 0x0E, 0x79, 0x95, 0x57, 0xB4, 0xBD, 0x26, 0xEF, 0xD6, 0x01,
	0xD1, 0xEB, 0x16, 0x0A, 0xBB, 0x8E, 0x0B, 0xB5, 0xC5, 0xC5, 0x8A, 0x55,
	0xAB, 0xD3, 0xAC, 0xEA, 0x91, 0x4B, 0x29, 0xCC, 0x19, 0xA4, 0x32, 0x25,
	0x4E, 0x2A, 0xF1, 0x65, 0x44, 0xD0, 0x02, 0xCE, 0xAA, 0xCE, 0x49, 0xB4,
	0xEA, 0x9F, 0x7C, 0x83, 0xB0, 0x40, 0x7B, 0xE7, 0x43, 0xAB, 0xA7, 0x6C,
	0xA3, 0x8F, 0x7D, 0x89, 0x81, 0xFA, 0x4C, 0xA5, 0xFF, 0xD5, 0x8E, 0xC3,
	0xCE, 0x4B, 0xE0, 0xB5, 0xD8, 0xB3, 0x8E, 0x45, 0xCF, 0x76, 0xC0, 0xED,
	0x40, 0x2B, 0xFD, 0x53, 0x0F, 0xB0, 0xA7, 0xD5, 0x3B, 0x0D, 0xB1, 0x8A,
	0xA2, 0x03, 0xDE, 0x31, 0xAD, 0xCC, 0x77, 0xEA, 0x6F, 0x7B, 0x3E, 0xD6,
	0xDF, 0x91, 0x22, 0x12, 0xE6, 0xBE, 0xFA, 0xD8, 0x32, 0xFC, 0x10, 0x63,
	0x14, 0x51, 0x72, 0xDE, 0x5D, 0xD6, 0x16, 0x93, 0xBD, 0x29, 0x68, 0x33,
	0xEF, 0x3A, 0x66, 0xEC, 0x07, 0x8A, 0x26, 0xDF, 0x13, 0xD7, 0x57, 0x65,
	0x78, 0x27, 0xDE, 0x5E, 0x49, 0x14, 0x00, 0xA2, 0x00, 0x7F, 0x9A, 0xA8,
	0x21, 0xB6, 0xA9, 0xB1, 0x95, 0xB0, 0xA5, 0xB9, 0x0D, 0x16, 0x11, 0xDA,
	0xC7, 0x6C, 0x48, 0x3C, 0x40, 0xE0, 0x7E, 0x0D, 0x5A, 0xCD, 0x56, 0x3C,
	0xD1, 0x97, 0x05, 0xB9, 0xCB, 0x4B, 0xED, 0x39, 0x4B, 0x9C, 0xC4, 0x3F,
	0xD2, 0x55, 0x13, 0x6E, 0x24, 0xB0, 0xD6, 0x71, 0xFA, 0xF4, 0xC1, 0xBA,
	0xCC, 0xED, 0x1B, 0xF5, 0xFE, 0x81, 0x41, 0xD8, 0x00, 0x98, 0x3D, 0x3A,
	0xC8, 0xAE, 0x7A, 0x98, 0x37, 0x18, 0x05, 0x95
};

static const unsigned char TA0_RSA_E[] = {
	0x01, 0x00, 0x01
};

static const br_x509_trust_anchor TAs[1] = {
	{
		{ (unsigned char *)TA0_DN, sizeof TA0_DN },
		BR_X509_TA_CA,
		{
			BR_KEYTYPE_RSA,
			{ .rsa = {
				(unsigned char *)TA0_RSA_N, sizeof TA0_RSA_N,
				(unsigned char *)TA0_RSA_E, sizeof TA0_RSA_E,
			} }
		}
	}
};

#define TAs_NUM   1

void setup() {
  // put your setup code here, to run once:

  Serial.begin(115200);
  Serial.println("\n\n\nStarted\n\n");

  WiFi.begin(ssid, password);
 
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.println("Connecting to WiFi..");
  }
 
  Serial.println("Connected to the WiFi network");

  const char *localTZ = "CET-1CEST-2,M3.5.0/02:00:00,M10.5.0/03:00:00";
  configTzTime(localTZ, "pool.ntp.org", "time.nist.gov");

  Serial.print(F("(setup) Wait for time"));
  time_t epoch;
  for(;;) {
    Serial.write('.');
    time(&epoch);
    if(epoch >= 3600) break;
    delay(500);
  }

  struct tm timeinfo;
  if(!getLocalTime(&timeinfo)){
    Serial.println("Failed to obtain time");
    return;
  }
  Serial.println(&timeinfo, "\n%A, %B %d %Y %H:%M:%S");

  Serial.printf("Epoch is %lu\n", time(NULL));



  const char *host, *port, *path;
  int fd;
  static br_ssl_client_context sc;
  static br_x509_minimal_context xc;
  static unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
  static br_sslio_context ioc;

  host = "www.google.com";
  port = "443";
  path = "/";

  /*
   * Ignore SIGPIPE to avoid crashing in case of abrupt socket close.
   */
//  signal(SIGPIPE, SIG_IGN); // signal() not supported by ESP32 IDF?

  /*
   * Open the socket to the target server.
   */
  fd = host_connect(host, port);
  if (fd < 0) {
    return;
  }

  Serial.println("After host_connect");

  /*
   * Initialise the client context:
   * -- Use the "full" profile (all supported algorithms).
   * -- The provided X.509 validation engine is initialised, with
   *    the hardcoded trust anchor.
   */
  br_ssl_client_init_full(&sc, &xc, TAs, TAs_NUM);
  
  Serial.println("After br_ssl_client_init_full");

  /*
   * Set the I/O buffer to the provided array. We allocated a
   * buffer large enough for full-duplex behaviour with all
   * allowed sizes of SSL records, hence we set the last argument
   * to 1 (which means "split the buffer into separate input and
   * output areas").
   */
  br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);

  /*
   * Reset the client context, for a new handshake. We provide the
   * target host name: it will be used for the SNI extension. The
   * last parameter is 0: we are not trying to resume a session.
   */
  br_ssl_client_reset(&sc, host, 0);

  /*
   * Initialise the simplified I/O wrapper context, to use our
   * SSL client context, and the two callbacks for socket I/O.
   */
  br_sslio_init(&ioc, &sc.eng, sock_read, &fd, sock_write, &fd);

  Serial.println("After br_sslio_init");

  /*
   * Note that while the context has, at that point, already
   * assembled the ClientHello to send, nothing happened on the
   * network yet. Real I/O will occur only with the next call.
   *
   * We write our simple HTTP request. We could test each call
   * for an error (-1), but this is not strictly necessary, since
   * the error state "sticks": if the context fails for any reason
   * (e.g. bad server certificate), then it will remain in failed
   * state and all subsequent calls will return -1 as well.
   */
  br_sslio_write_all(&ioc, "GET ", 4);
  Serial.println("After first write");
  br_sslio_write_all(&ioc, path, strlen(path));
  br_sslio_write_all(&ioc, " HTTP/1.0\r\nHost: ", 17);
  br_sslio_write_all(&ioc, host, strlen(host));
  br_sslio_write_all(&ioc, "\r\n\r\n", 4);

  Serial.println("After write");

  /*
   * SSL is a buffered protocol: we make sure that all our request
   * bytes are sent onto the wire.
   */
  br_sslio_flush(&ioc);

  Serial.println("After flush");

  /*
   * Read the server's response. We use here a small 512-byte buffer,
   * but most of the buffering occurs in the client context: the
   * server will send full records (up to 16384 bytes worth of data
   * each), and the client context buffers one full record at a time.
   */
  uint32_t startMillis = millis();

  uint32_t pageSize = 0;
  uint32_t pageMillis = millis();
  for (;;) {
    if(millis() - startMillis > 10000) {
      Serial.println("TIMEOUT");
      break;
    }
    int rlen;
    unsigned char tmp[512];

    rlen = br_sslio_read(&ioc, tmp, sizeof tmp);
    if (rlen < 0) {
      break;
    }
    fwrite(tmp, 1, rlen, stdout);
    pageSize += rlen;
    startMillis = millis();
  }

  /*
   * Close the socket.
   */
  close(fd);

  Serial.println("\nAfter close");

  Serial.printf("Engine server name: '%s'\n", br_ssl_engine_get_server_name(&sc.eng));

  /*
   * Check whether we closed properly or not. If the engine is
   * closed, then its error status allows to distinguish between
   * a normal closure and a SSL error.
   *
   * If the engine is NOT closed, then this means that the
   * underlying network socket was closed or failed in some way.
   * Note that many Web servers out there do not properly close
   * their SSL connections (they don't send a close_notify alert),
   * which will be reported here as "socket closed without proper
   * SSL termination".
   */
  if (br_ssl_engine_current_state(&sc.eng) == BR_SSL_CLOSED) {
    int err;

    err = br_ssl_engine_last_error(&sc.eng);
    if (err == 0) {
      Serial.println("closed.");

      pageMillis = millis() - pageMillis;
      Serial.printf("Size %lu, duration %lu, rate %f kB / s\n", pageSize, pageMillis, float(pageSize)/ pageMillis);

      return;
    } else {
      Serial.printf("SSL error %d\n", err);

      pageMillis = millis() - pageMillis;
      Serial.printf("Size %lu, duration %lu, rate %f kB / s\n", pageSize, pageMillis, float(pageSize)/ pageMillis);

      return;
    }
  } else {
    Serial.println("socket closed without proper SSL termination");
    return;
  }

  Serial.println("Done");
}

void loop() {
  // put your main code here, to run repeatedly:

}
