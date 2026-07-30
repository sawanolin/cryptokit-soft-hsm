/*
 * Windows Winsock transport used by the x64 SDF client SDK.
 * The Windows artifact is client-only; daemon-side entry points reject use.
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "transport_interface.h"
#include "protocol.h"
#include "sdfx_defaults.h"

static SOCKET g_client_socket = INVALID_SOCKET;
static char g_server_host[256] = SDFX_DEFAULT_TCP_HOST;
static uint16_t g_server_port = SDFX_DEFAULT_TCP_PORT;
static int g_winsock_started = 0;

static int ensure_winsock(void)
{
    if (g_winsock_started) {
        return 0;
    }
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        return -1;
    }
    g_winsock_started = 1;
    return 0;
}

int transport_init_with_config(const transport_config_t *config)
{
    if (config == NULL || ensure_winsock() != 0) {
        return -1;
    }
    const char *host = config->address != NULL
        ? config->address : SDFX_DEFAULT_TCP_HOST;
    strncpy(g_server_host, host, sizeof(g_server_host) - 1);
    g_server_host[sizeof(g_server_host) - 1] = '\0';
    g_server_port = config->port != 0
        ? config->port : SDFX_DEFAULT_TCP_PORT;
    return 0;
}

int transport_init(const transport_config_t *config)
{
    return transport_init_with_config(config);
}

int transport_connect(const char *address)
{
    char host[256];
    char service[16];
    const char *selected_host = g_server_host;
    uint16_t selected_port = g_server_port;

    if (address != NULL && address[0] != '\0') {
        const char *colon = strrchr(address, ':');
        if (colon != NULL) {
            size_t host_len = (size_t)(colon - address);
            if (host_len == 0 || host_len >= sizeof(host)) {
                return -1;
            }
            memcpy(host, address, host_len);
            host[host_len] = '\0';
            selected_host = host;
            long parsed = strtol(colon + 1, NULL, 10);
            if (parsed < 1 || parsed > 65535) {
                return -1;
            }
            selected_port = (uint16_t)parsed;
        }
    }

    snprintf(service, sizeof(service), "%u", (unsigned)selected_port);
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (getaddrinfo(selected_host, service, &hints, &addresses) != 0) {
        return -1;
    }

    SOCKET connected = INVALID_SOCKET;
    for (struct addrinfo *entry = addresses; entry != NULL; entry = entry->ai_next) {
        SOCKET candidate = socket(entry->ai_family, entry->ai_socktype,
                                  entry->ai_protocol);
        if (candidate == INVALID_SOCKET) {
            continue;
        }
        if (connect(candidate, entry->ai_addr, (int)entry->ai_addrlen) == 0) {
            connected = candidate;
            break;
        }
        closesocket(candidate);
    }
    freeaddrinfo(addresses);
    if (connected == INVALID_SOCKET) {
        return -1;
    }
    g_client_socket = connected;
    return 0;
}

ssize_t transport_send(const transport_client_t *client, const void *data,
                       size_t length)
{
    SOCKET socket_value = client != NULL
        ? (SOCKET)(uintptr_t)client->fd : g_client_socket;
    if (socket_value == INVALID_SOCKET || data == NULL || length == 0) {
        return -1;
    }
    size_t total = 0;
    while (total < length) {
        size_t remaining = length - total;
        int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
        int sent = send(socket_value, (const char *)data + total, chunk, 0);
        if (sent == SOCKET_ERROR || sent == 0) {
            return -1;
        }
        total += (size_t)sent;
    }
    return (ssize_t)total;
}

ssize_t transport_recv(const transport_client_t *client, void *buffer,
                       size_t length)
{
    SOCKET socket_value = client != NULL
        ? (SOCKET)(uintptr_t)client->fd : g_client_socket;
    if (socket_value == INVALID_SOCKET || buffer == NULL || length == 0) {
        return -1;
    }
    int chunk = length > INT_MAX ? INT_MAX : (int)length;
    int received = recv(socket_value, (char *)buffer, chunk, 0);
    return received == SOCKET_ERROR ? -1 : (ssize_t)received;
}

int transport_recv_message(const transport_client_t *client, void *buffer,
                           size_t buffer_size, size_t *received_size)
{
    if (buffer == NULL || received_size == NULL ||
        buffer_size < sizeof(sdfx_message_header_t)) {
        return -1;
    }
    size_t total = 0;
    while (total < sizeof(sdfx_message_header_t)) {
        ssize_t got = transport_recv(client, (BYTE *)buffer + total,
                                     sizeof(sdfx_message_header_t) - total);
        if (got <= 0) {
            return got == 0 && total == 0 ? 2 : -1;
        }
        total += (size_t)got;
    }
    const sdfx_message_t *message = (const sdfx_message_t *)buffer;
    if (sdfx_ntohl(message->header.magic) != SDFX_MAGIC) {
        return -1;
    }
    size_t payload_length = sdfx_ntohl(message->header.length);
    size_t message_length = sizeof(sdfx_message_header_t) + payload_length;
    if (message_length > buffer_size || message_length > SDFX_MAX_MESSAGE_SIZE) {
        return -1;
    }
    while (total < message_length) {
        ssize_t got = transport_recv(client, (BYTE *)buffer + total,
                                     message_length - total);
        if (got <= 0) {
            return -1;
        }
        total += (size_t)got;
    }
    *received_size = total;
    return 0;
}

void transport_close_client(transport_client_t *client)
{
    if (client != NULL && client->fd != (intptr_t)INVALID_SOCKET) {
        closesocket((SOCKET)(uintptr_t)client->fd);
        client->fd = (intptr_t)INVALID_SOCKET;
    }
}

void transport_close(void)
{
    if (g_client_socket != INVALID_SOCKET) {
        shutdown(g_client_socket, SD_BOTH);
        closesocket(g_client_socket);
        g_client_socket = INVALID_SOCKET;
    }
}

void transport_cleanup(void)
{
    transport_close();
    if (g_winsock_started) {
        WSACleanup();
        g_winsock_started = 0;
    }
}

int transport_listen(void)
{
    return -1;
}

int transport_accept(transport_client_t *client)
{
    (void)client;
    return -1;
}

const char *transport_get_type(void)
{
    return "Windows Winsock TCP";
}
