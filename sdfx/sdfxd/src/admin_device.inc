/* Device identity persistence used by the authenticated Web management plane. */

#define SDFX_DEVICE_INFO_FILE "device-info.bin"

static pthread_mutex_t g_device_info_mutex = PTHREAD_MUTEX_INITIALIZER;

static int admin_device_info_path(char *path, size_t path_len)
{
    const char *root = getenv("SDFX_DATA_DIR");
    if (root == NULL || root[0] == '\0') {
        root = "/var/lib/sdfx";
    }
    int n = snprintf(path, path_len, "%s/%s", root, SDFX_DEVICE_INFO_FILE);
    return n > 0 && (size_t)n < path_len ? SDR_OK : SDR_FILEWERR;
}

static int admin_device_info_save(const DEVICEINFO *info)
{
    char path[512];
    char temporary[560];
    if (admin_device_info_path(path, sizeof(path)) != SDR_OK) {
        return SDR_FILEWERR;
    }
    int n = snprintf(temporary, sizeof(temporary), "%s.tmp.%ld",
                     path, (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(temporary)) {
        return SDR_FILEWERR;
    }
    int fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        return SDR_FILEWERR;
    }
    ssize_t written = write(fd, info, sizeof(*info));
    if (written != (ssize_t)sizeof(*info) || fsync(fd) != 0) {
        close(fd);
        unlink(temporary);
        return SDR_FILEWERR;
    }
    close(fd);
    if (rename(temporary, path) != 0) {
        unlink(temporary);
        return SDR_FILEWERR;
    }
    return SDR_OK;
}

static int admin_device_text_valid(const BYTE *data, uint32_t length)
{
    if (data == NULL || length == 0) {
        return 0;
    }
    for (uint32_t i = 0; i < length; ++i) {
        if (data[i] < 0x20 || data[i] == 0x7f) {
            return 0;
        }
    }
    return 1;
}

static int admin_device_info_update(const BYTE *data, uint32_t data_len,
                                    uint32_t issuer_len, uint32_t device_len,
                                    uint32_t serial_len)
{
    if (issuer_len > sizeof(g_device_info.IssuerName) ||
        device_len > sizeof(g_device_info.DeviceName) ||
        serial_len > sizeof(g_device_info.DeviceSerial) ||
        issuer_len + device_len + serial_len != data_len ||
        !admin_device_text_valid(data, issuer_len) ||
        !admin_device_text_valid(data + issuer_len, device_len) ||
        !admin_device_text_valid(data + issuer_len + device_len, serial_len)) {
        return SDR_INARGERR;
    }

    pthread_mutex_lock(&g_device_info_mutex);
    DEVICEINFO updated = g_device_info;
    memset(updated.IssuerName, 0, sizeof(updated.IssuerName));
    memset(updated.DeviceName, 0, sizeof(updated.DeviceName));
    memset(updated.DeviceSerial, 0, sizeof(updated.DeviceSerial));
    memcpy(updated.IssuerName, data, issuer_len);
    memcpy(updated.DeviceName, data + issuer_len, device_len);
    memcpy(updated.DeviceSerial, data + issuer_len + device_len, serial_len);
    int ret = admin_device_info_save(&updated);
    if (ret == SDR_OK) {
        g_device_info = updated;
    }
    pthread_mutex_unlock(&g_device_info_mutex);
    return ret;
}

static int admin_device_info_load(void)
{
    char path[512];
    if (admin_device_info_path(path, sizeof(path)) != SDR_OK) {
        return SDR_FILEWERR;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return errno == ENOENT ? SDR_OK : SDR_FILENOEXIST;
    }
    DEVICEINFO stored;
    ssize_t got = read(fd, &stored, sizeof(stored));
    BYTE trailing = 0;
    ssize_t extra = read(fd, &trailing, 1);
    close(fd);
    if (got != (ssize_t)sizeof(stored) || extra != 0 ||
        stored.BufferSize == 0 || stored.StandardVersion == 0) {
        return SDR_FILESIZEERR;
    }
    pthread_mutex_lock(&g_device_info_mutex);
    g_device_info = stored;
    pthread_mutex_unlock(&g_device_info_mutex);
    return SDR_OK;
}

static void admin_device_info_reset_runtime(void)
{
    DEVICEINFO reset = {
        .IssuerName = "SDFX Project",
        .DeviceName = "SDFX-1.0",
        .DeviceSerial = "SW000001",
        .DeviceVersion = 0x00010000,
        .StandardVersion = 0x00020023,
        .AsymAlgAbility = {SGD_SM2_1 | SGD_SM2_3, 256},
        .SymAlgAbility = SGD_SM4_ECB | SGD_SM4_CBC | SGD_SM4_CFB |
                         SGD_SM4_OFB | SGD_SM4_CTR | SGD_SM4_MAC,
        .HashAlgAbility = SGD_SM3,
        .BufferSize = 4096
    };
    pthread_mutex_lock(&g_device_info_mutex);
    g_device_info = reset;
    pthread_mutex_unlock(&g_device_info_mutex);
}
