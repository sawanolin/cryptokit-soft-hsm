/* sdfxd-owned backup, restore and reset operations. */
#include <dirent.h>
#include <sys/wait.h>

#define SDFX_BACKUP_SUFFIX ".sdfxbak"
#define SDFX_BACKUP_MAX_FILE (64ULL * 1024ULL * 1024ULL)
#define SDFX_BACKUP_MAX_TOTAL (256ULL * 1024ULL * 1024ULL)

static int maintenance_id_valid(const BYTE *id, uint32_t id_len)
{
    if (id == NULL || id_len != 32) {
        return 0;
    }
    for (uint32_t i = 0; i < id_len; ++i) {
        if (!((id[i] >= '0' && id[i] <= '9') ||
              (id[i] >= 'a' && id[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int maintenance_no_sessions(daemon_context_t *ctx)
{
    pthread_mutex_lock(&ctx->sessions_mutex);
    int available = ctx->active_sessions_count == 0;
    pthread_mutex_unlock(&ctx->sessions_mutex);
    return available;
}

static int backup_dir_path(char *path, size_t path_len)
{
    int n = snprintf(path, path_len, "%s/backups", storage_root());
    return n > 0 && (size_t)n < path_len ? SDR_OK : SDR_FILEWERR;
}

static int backup_file_path(const BYTE *id, uint32_t id_len,
                            char *path, size_t path_len)
{
    if (!maintenance_id_valid(id, id_len)) {
        return SDR_INARGERR;
    }
    char directory[512];
    if (backup_dir_path(directory, sizeof(directory)) != SDR_OK) {
        return SDR_FILEWERR;
    }
    int n = snprintf(path, path_len, "%s/%.*s%s", directory, (int)id_len,
                     (const char *)id, SDFX_BACKUP_SUFFIX);
    return n > 0 && (size_t)n < path_len ? SDR_OK : SDR_FILEWERR;
}

static int run_archive_tool(const char *operation, const char *archive,
                            const char *directory)
{
    pid_t child = fork();
    if (child < 0) {
        return SDR_FILEWERR;
    }
    if (child == 0) {
        if (strcmp(operation, "create") == 0) {
            execl("/bin/tar", "tar", "-cf", archive, "-C", directory,
                  "keys", "files", "web", "device-info.bin", (char *)NULL);
        } else {
            execl("/bin/tar", "tar", "-xf", archive, "-C", directory,
                  (char *)NULL);
        }
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            return SDR_FILEWERR;
        }
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0
        ? SDR_OK : SDR_FILEWERR;
}

static uint64_t tar_octal(const BYTE *value, size_t length, int *valid)
{
    uint64_t result = 0;
    size_t i = 0;
    while (i < length && (value[i] == ' ' || value[i] == '\0')) {
        ++i;
    }
    int digits = 0;
    for (; i < length && value[i] != '\0' && value[i] != ' '; ++i) {
        if (value[i] < '0' || value[i] > '7' ||
            result > (UINT64_MAX >> 3)) {
            *valid = 0;
            return 0;
        }
        result = (result << 3) + (uint64_t)(value[i] - '0');
        digits = 1;
    }
    if (!digits) {
        result = 0;
    }
    return result;
}

static int tar_path_allowed(const char *path)
{
    while (path[0] == '.' && path[1] == '/') {
        path += 2;
    }
    if (path[0] == '\0' || path[0] == '/' || strchr(path, '\\') != NULL ||
        strstr(path, "//") != NULL) {
        return 0;
    }
    const char *cursor = path;
    while (*cursor != '\0') {
        const char *end = strchr(cursor, '/');
        size_t length = end == NULL ? strlen(cursor) : (size_t)(end - cursor);
        if (length == 0 || (length == 1 && cursor[0] == '.') ||
            (length == 2 && cursor[0] == '.' && cursor[1] == '.')) {
            return 0;
        }
        if (end == NULL) {
            break;
        }
        cursor = end + 1;
    }
    return strcmp(path, "device-info.bin") == 0 ||
           strncmp(path, "keys/", 5) == 0 || strcmp(path, "keys") == 0 ||
           strncmp(path, "files/", 6) == 0 || strcmp(path, "files") == 0 ||
           strncmp(path, "web/", 4) == 0 || strcmp(path, "web") == 0;
}

static int validate_backup_archive(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return errno == ENOENT ? SDR_FILENOEXIST : SDR_FILEWERR;
    }
    uint64_t total = 0;
    int has_state = 0;
    int has_device = 0;
    int saw_end = 0;
    BYTE header[512];
    while (read(fd, header, sizeof(header)) == (ssize_t)sizeof(header)) {
        int all_zero = 1;
        for (size_t i = 0; i < sizeof(header); ++i) {
            if (header[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (all_zero) {
            saw_end = 1;
            break;
        }

        unsigned stored_checksum = 0;
        int checksum_valid = 1;
        stored_checksum = (unsigned)tar_octal(header + 148, 8, &checksum_valid);
        unsigned computed_checksum = 0;
        for (size_t i = 0; i < sizeof(header); ++i) {
            computed_checksum += (i >= 148 && i < 156) ? ' ' : header[i];
        }
        if (!checksum_valid || stored_checksum != computed_checksum) {
            close(fd);
            return SDR_FILESIZEERR;
        }

        char name[257];
        size_t name_len = strnlen((const char *)header, 100);
        size_t prefix_len = strnlen((const char *)header + 345, 155);
        if (name_len == 0 || name_len >= sizeof(name) ||
            prefix_len + name_len + 2 > sizeof(name)) {
            close(fd);
            return SDR_FILESIZEERR;
        }
        if (prefix_len != 0) {
            memcpy(name, header + 345, prefix_len);
            name[prefix_len] = '/';
            memcpy(name + prefix_len + 1, header, name_len);
            name[prefix_len + name_len + 1] = '\0';
        } else {
            memcpy(name, header, name_len);
            name[name_len] = '\0';
        }
        const char *normalized = name;
        while (normalized[0] == '.' && normalized[1] == '/') {
            normalized += 2;
        }
        BYTE type = header[156];
        if (!tar_path_allowed(name) ||
            !(type == '\0' || type == '0' || type == '5')) {
            close(fd);
            return SDR_PARDENY;
        }
        if (strcmp(normalized, "web/state.json") == 0) {
            has_state = 1;
        } else if (strcmp(normalized, "device-info.bin") == 0) {
            has_device = 1;
        }

        int size_valid = 1;
        uint64_t size = tar_octal(header + 124, 12, &size_valid);
        if (!size_valid || size > SDFX_BACKUP_MAX_FILE ||
            total > SDFX_BACKUP_MAX_TOTAL - size) {
            close(fd);
            return SDR_FILESIZEERR;
        }
        total += size;
        uint64_t padded = (size + 511U) & ~511ULL;
        if (padded > (uint64_t)INT64_MAX ||
            lseek(fd, (off_t)padded, SEEK_CUR) < 0) {
            close(fd);
            return SDR_FILESIZEERR;
        }
    }
    BYTE trailing;
    ssize_t extra = read(fd, &trailing, 1);
    close(fd);
    return saw_end && extra >= 0 && has_state && has_device
        ? SDR_OK : SDR_FILESIZEERR;
}

static int remove_tree(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0) {
        return errno == ENOENT ? SDR_OK : SDR_FILEWERR;
    }
    if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode)) {
        return unlink(path) == 0 ? SDR_OK : SDR_FILEWERR;
    }
    DIR *directory = opendir(path);
    if (directory == NULL) {
        return SDR_FILEWERR;
    }
    int result = SDR_OK;
    struct dirent *entry;
    while (result == SDR_OK && (entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char child[1024];
        int n = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        result = n > 0 && (size_t)n < sizeof(child)
            ? remove_tree(child) : SDR_FILEWERR;
    }
    closedir(directory);
    if (result == SDR_OK && rmdir(path) != 0) {
        result = SDR_FILEWERR;
    }
    return result;
}

static int move_restored_item(const char *staging, const char *name)
{
    char source[1024];
    char destination[1024];
    int a = snprintf(source, sizeof(source), "%s/%s", staging, name);
    int b = snprintf(destination, sizeof(destination), "%s/%s",
                     storage_root(), name);
    if (a <= 0 || b <= 0 || (size_t)a >= sizeof(source) ||
        (size_t)b >= sizeof(destination)) {
        return SDR_FILEWERR;
    }
    int result = remove_tree(destination);
    if (result == SDR_OK && rename(source, destination) != 0) {
        result = SDR_FILEWERR;
    }
    return result;
}

int backup_admin_create(daemon_context_t *ctx, const BYTE *id, uint32_t id_len)
{
    if (!maintenance_no_sessions(ctx)) {
        return SDR_STEPERR;
    }
    char directory[512];
    char final_path[640];
    char temporary[700];
    if (backup_dir_path(directory, sizeof(directory)) != SDR_OK ||
        backup_file_path(id, id_len, final_path, sizeof(final_path)) != SDR_OK ||
        ensure_dir(directory) != SDR_OK) {
        return SDR_INARGERR;
    }
    int n = snprintf(temporary, sizeof(temporary), "%s.tmp.%ld",
                     final_path, (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(temporary) ||
        access(final_path, F_OK) == 0) {
        return access(final_path, F_OK) == 0 ? SDR_FILEEXISTS : SDR_FILEWERR;
    }
    pthread_mutex_lock(&g_storage_mutex);
    int result = run_archive_tool("create", temporary, storage_root());
    if (result == SDR_OK) {
        result = validate_backup_archive(temporary);
    }
    if (result == SDR_OK && rename(temporary, final_path) != 0) {
        result = SDR_FILEWERR;
    }
    if (result != SDR_OK) {
        unlink(temporary);
    }
    pthread_mutex_unlock(&g_storage_mutex);
    return result;
}

int backup_admin_list(BYTE *output, uint32_t *output_len)
{
    if (output == NULL || output_len == NULL || *output_len < 3) {
        return SDR_INARGERR;
    }
    char directory_path[512];
    if (backup_dir_path(directory_path, sizeof(directory_path)) != SDR_OK ||
        ensure_dir(directory_path) != SDR_OK) {
        return SDR_FILEWERR;
    }
    DIR *directory = opendir(directory_path);
    if (directory == NULL) {
        return SDR_FILEWERR;
    }
    size_t capacity = *output_len;
    size_t used = 1;
    unsigned count = 0;
    output[0] = '[';
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        size_t length = strlen(entry->d_name);
        size_t suffix = strlen(SDFX_BACKUP_SUFFIX);
        if (length != 32 + suffix ||
            strcmp(entry->d_name + 32, SDFX_BACKUP_SUFFIX) != 0 ||
            !maintenance_id_valid((const BYTE *)entry->d_name, 32)) {
            continue;
        }
        char path[700];
        int p = snprintf(path, sizeof(path), "%s/%s",
                         directory_path, entry->d_name);
        struct stat st;
        if (p <= 0 || (size_t)p >= sizeof(path) ||
            lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }
        int n = snprintf((char *)output + used, capacity - used,
            "%s{\"id\":\"%.*s\",\"size\":%llu,\"created_at\":%lld}",
            count == 0 ? "" : ",", 32, entry->d_name,
            (unsigned long long)st.st_size, (long long)st.st_mtime);
        if (n < 0 || (size_t)n >= capacity - used) {
            closedir(directory);
            return SDR_NOBUFFER;
        }
        used += (size_t)n;
        ++count;
    }
    closedir(directory);
    if (used + 2 > capacity) {
        return SDR_NOBUFFER;
    }
    output[used++] = ']';
    output[used] = '\0';
    *output_len = (uint32_t)used;
    return SDR_OK;
}

int backup_admin_delete(const BYTE *id, uint32_t id_len)
{
    char path[640];
    if (backup_file_path(id, id_len, path, sizeof(path)) != SDR_OK) {
        return SDR_INARGERR;
    }
    return unlink(path) == 0
        ? SDR_OK : (errno == ENOENT ? SDR_FILENOEXIST : SDR_FILEWERR);
}

int backup_admin_restore(daemon_context_t *ctx, const BYTE *id, uint32_t id_len)
{
    if (!maintenance_no_sessions(ctx)) {
        return SDR_STEPERR;
    }
    char archive[640];
    char staging[700];
    if (backup_file_path(id, id_len, archive, sizeof(archive)) != SDR_OK) {
        return SDR_INARGERR;
    }
    int result = validate_backup_archive(archive);
    int n = snprintf(staging, sizeof(staging), "%s/.restore-%.*s",
                     storage_root(), (int)id_len, (const char *)id);
    if (result != SDR_OK || n <= 0 || (size_t)n >= sizeof(staging) ||
        mkdir(staging, 0700) != 0) {
        return result != SDR_OK ? result : SDR_FILEWERR;
    }
    pthread_mutex_lock(&g_storage_mutex);
    result = run_archive_tool("restore", archive, staging);
    const char *items[] = {"keys", "files", "web", "master", "device-info.bin"};
    for (size_t i = 0; result == SDR_OK &&
         i < sizeof(items) / sizeof(items[0]); ++i) {
        result = move_restored_item(staging, items[i]);
    }
    remove_tree(staging);
    pthread_mutex_unlock(&g_storage_mutex);
    return result;
}

int backup_admin_reset(daemon_context_t *ctx)
{
    if (!maintenance_no_sessions(ctx)) {
        return SDR_STEPERR;
    }
    pthread_mutex_lock(&g_storage_mutex);
    const char *items[] = {"keys", "files", "web", "master", "device-info.bin"};
    int result = SDR_OK;
    for (size_t i = 0; result == SDR_OK &&
         i < sizeof(items) / sizeof(items[0]); ++i) {
        char path[700];
        int n = snprintf(path, sizeof(path), "%s/%s",
                         storage_root(), items[i]);
        result = n > 0 && (size_t)n < sizeof(path)
            ? remove_tree(path) : SDR_FILEWERR;
    }
    if (result == SDR_OK) {
        result = ensure_storage_tree();
    }
    pthread_mutex_unlock(&g_storage_mutex);
    return result;
}
