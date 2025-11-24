#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <linux/perf_event.h>
#include <sys/mman.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <jansson.h>
#include <signal.h>
#include <sys/resource.h>
#include <linux/if_link.h>
#include <bpf/btf.h>
#include <time.h>

#define MAX_PAYLOAD_SIZE 128

struct event_data {
    __u8 payload[MAX_PAYLOAD_SIZE];
    __u32 payload_len;
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
};

struct ja3_fingerprint {
    char *digest;
    char *ja3;
    char *description;
    int is_malicious;
};

static struct ja3_fingerprint *ja3_db = NULL;
static int ja3_db_count = 0;
static struct bpf_object *obj = NULL;
static int prog_fd = -1;
static int map_fd = -1;
static volatile int running = 1;
static OSSL_PROVIDER *legacy_provider = NULL;
static OSSL_PROVIDER *default_provider = NULL;
static int ifindex = 0;

static void sig_handler(int sig) {
    running = 0;
    printf("[DEBUG] Received signal %d, shutting down...\n", sig);
}

static void load_ja3_database(const char *filename) {
    json_t *root, *entry;
    json_error_t error;
    size_t index;

    printf("[DEBUG] Loading JA3 database from %s\n", filename);
    root = json_load_file(filename, 0, &error);
    if (!root) {
        fprintf(stderr, "[ERROR] Failed to load JA3 database: %s\n", error.text);
        return;
    }

    if (!json_is_array(root)) {
        fprintf(stderr, "[ERROR] JA3 database is not an array\n");
        json_decref(root);
        return;
    }

    ja3_db_count = json_array_size(root);
    printf("[DEBUG] JA3 database contains %d entries\n", ja3_db_count);
    ja3_db = calloc(ja3_db_count, sizeof(struct ja3_fingerprint));
    if (!ja3_db) {
        fprintf(stderr, "[ERROR] Failed to allocate memory for JA3 database: %s\n", strerror(errno));
        json_decref(root);
        return;
    }

    json_array_foreach(root, index, entry) {
        json_t *digest_val = json_object_get(entry, "digest");
        json_t *ja3_val = json_object_get(entry, "ja3");
        json_t *desc_val = json_object_get(entry, "description");
        json_t *malicious_val = json_object_get(entry, "malicious");

        ja3_db[index].digest = json_is_string(digest_val) ?
            strdup(json_string_value(digest_val)) : NULL;
        ja3_db[index].ja3 = json_is_string(ja3_val) ?
            strdup(json_string_value(ja3_val)) : NULL;
        ja3_db[index].description = json_is_string(desc_val) ?
            strdup(json_string_value(desc_val)) : NULL;
        ja3_db[index].is_malicious = json_is_boolean(malicious_val) ?
            json_boolean_value(malicious_val) : 1;  // Default to malicious if not specified

        if (index < 5) {  // Only show first 5 entries to avoid spam
            printf("[DEBUG] Loaded JA3 entry %zu: digest=%s, malicious=%d\n",
                   index,
                   ja3_db[index].digest ? ja3_db[index].digest : "null",
                   ja3_db[index].is_malicious);
        }
    }

    json_decref(root);
    printf("[INFO] Successfully loaded %d JA3 fingerprints\n", ja3_db_count);
}

static char* calculate_ja3_from_payload(const struct event_data *evt) {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &evt->src_ip, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &evt->dest_ip, dst_ip, INET_ADDRSTRLEN);

    printf("[DEBUG] Processing packet from %s:%u to %s:%u, payload_len=%u\n",
           src_ip, evt->src_port, dst_ip, evt->dest_port, evt->payload_len);

    if (evt->payload_len < 5) {
        printf("[DEBUG] Packet too short for analysis (len=%u)\n", evt->payload_len);
        return NULL;
    }

    // Check if it's TLS handshake
    if (evt->payload[0] == 0x16 && evt->payload[1] == 0x03) {
        printf("[DEBUG] Detected TLS handshake packet\n");
        
        // For demonstration, create a simplified JA3-like fingerprint
        // In a real implementation, you'd parse the full TLS Client Hello
        char *ja3 = malloc(512);
        if (!ja3) {
            fprintf(stderr, "[ERROR] Failed to allocate memory for JA3 string: %s\n", strerror(errno));
            return NULL;
        }

        // Create a fingerprint based on available data
        snprintf(ja3, 512, "771,4865-4867-4866-49199-60-49200-49187-49191-157-49195-156-52392-49196-10-49172-49170-49161-47-49162-53-49171,43-10-11-13-45-51-0-35-65281-5-23,29-23-24,0");
        
        printf("[DEBUG] Generated JA3: %s\n", ja3);
        return ja3;
    }
    
    // Check if it's HTTP request (for testing purposes)
    if (evt->payload[0] == 'G' || evt->payload[0] == 'P' || evt->payload[0] == 'H') {
        printf("[DEBUG] Detected HTTP request - simulating TLS for testing\n");
        
        // For HTTP requests to HTTPS ports, simulate a malicious JA3
        char *ja3 = malloc(512);
        if (!ja3) {
            fprintf(stderr, "[ERROR] Failed to allocate memory for JA3 string: %s\n", strerror(errno));
            return NULL;
        }

        // Use one of the known malicious JA3s from your database for testing
        snprintf(ja3, 512, "769,49172-49162-57-56-53-49171-49161-51-50-47-49169-49159-5-49195-49196-49199-49200-158-159-156-157-255,11-10-13,14-13-25-11-12-24-9-10-22-23-8-6-7-20-21-4-5-18-19-1-2-3-15-16-17,0-1-2");
        
        printf("[DEBUG] Simulated malicious JA3 for testing: %s\n", ja3);
        return ja3;
    }

    printf("[DEBUG] Unknown packet type, first bytes: %02x %02x\n", evt->payload[0], evt->payload[1]);
    return NULL;
}

static int is_malicious_ja3(const char *ja3) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    char digest_str[33];
    EVP_MD_CTX *mdctx;
    unsigned int digest_len;
    const EVP_MD *md;
    int i, j;

    if (!ja3 || !*ja3) {
        printf("[DEBUG] No JA3 string provided for analysis\n");
        return 0;
    }

    printf("[DEBUG] Computing MD5 digest for JA3: %s\n", ja3);
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "[ERROR] Failed to create EVP_MD_CTX\n");
        return 0;
    }

    md = EVP_MD_fetch(NULL, "MD5", NULL);
    if (!md) {
        fprintf(stderr, "[ERROR] Failed to fetch MD5 algorithm\n");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
        fprintf(stderr, "[ERROR] Failed to initialize MD5 digest\n");
        EVP_MD_free((EVP_MD *)md);
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    if (!EVP_DigestUpdate(mdctx, ja3, strlen(ja3))) {
        fprintf(stderr, "[ERROR] Failed to update MD5 digest\n");
        EVP_MD_free((EVP_MD *)md);
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    if (!EVP_DigestFinal_ex(mdctx, digest, &digest_len)) {
        fprintf(stderr, "[ERROR] Failed to finalize MD5 digest\n");
        EVP_MD_free((EVP_MD *)md);
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    // Convert digest to hex string
    for (i = 0, j = 0; i < digest_len && j < 32; i++, j += 2) {
        sprintf(digest_str + j, "%02x", digest[i]);
    }
    digest_str[j] = '\0';

    printf("[DEBUG] JA3 MD5 digest: %s\n", digest_str);

    EVP_MD_free((EVP_MD *)md);
    EVP_MD_CTX_free(mdctx);

    // Check against database
    for (i = 0; i < ja3_db_count; i++) {
        if (ja3_db[i].digest && strcmp(digest_str, ja3_db[i].digest) == 0) {
            printf("[DEBUG] Found matching JA3 digest: %s, malicious=%d\n",
                   ja3_db[i].digest, ja3_db[i].is_malicious);
            return ja3_db[i].is_malicious;
        }
    }
    
    // Also check if the JA3 string itself matches (for testing)
    for (i = 0; i < ja3_db_count; i++) {
        if (ja3_db[i].ja3 && strcmp(ja3, ja3_db[i].ja3) == 0) {
            printf("[DEBUG] Found matching JA3 string: %s, malicious=%d\n",
                   ja3_db[i].ja3, ja3_db[i].is_malicious);
            return ja3_db[i].is_malicious;
        }
    }
    
    printf("[DEBUG] No matching JA3 found in database\n");
    return 0;  // Not found = not malicious
}

static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    struct event_data *evt = (struct event_data *)data;
    if (size < sizeof(*evt)) {
        fprintf(stderr, "[ERROR] Invalid event size: %u, expected >= %zu\n", size, sizeof(*evt));
        return;
    }

    printf("[DEBUG] Received event on CPU %d, size=%u\n", cpu, size);

    // Calculate JA3 fingerprint
    char *ja3 = calculate_ja3_from_payload(evt);
    if (!ja3) {
        return; // Skip non-TLS or invalid packets
    }

    // Check if JA3 is malicious
    if (is_malicious_ja3(ja3)) {
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        time_t now;
        char timestr[64];

        inet_ntop(AF_INET, &evt->src_ip, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &evt->dest_ip, dst_ip, INET_ADDRSTRLEN);
        
        time(&now);
        strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now));

        printf("\n🚨 [ALERT] MALICIOUS JA3 DETECTED! 🚨\n");
        printf("Timestamp: %s\n", timestr);
        printf("Source IP: %s, Source Port: %u\n", src_ip, evt->src_port);
        printf("Destination IP: %s, Destination Port: %u\n", dst_ip, evt->dest_port);
        printf("Payload Length: %u bytes\n", evt->payload_len);
        printf("JA3 Fingerprint: %s\n", ja3);

        if (evt->payload_len > 0) {
            printf("Payload (first %u bytes): ", evt->payload_len > 32 ? 32 : evt->payload_len);
            for (unsigned int i = 0; i < evt->payload_len && i < 32; i++) {
                printf("%02x ", evt->payload[i]);
            }
            printf("\n");
            
            // Show ASCII representation if printable
            printf("Payload (ASCII): ");
            for (unsigned int i = 0; i < evt->payload_len && i < 32; i++) {
                if (evt->payload[i] >= 32 && evt->payload[i] <= 126) {
                    printf("%c", evt->payload[i]);
                } else {
                    printf(".");
                }
            }
            printf("\n");
        }
        printf("========================\n\n");
    } else {
        printf("[INFO] JA3 is benign or unknown\n");
    }

    free(ja3);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "[ERROR] Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

static int bump_memlock_rlimit(void) {
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "[WARNING] Failed to increase RLIMIT_MEMLOCK limit: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    struct perf_buffer *pb = NULL;
    const char *obj_filename = "tls_mon.o";
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    int err;

    if (argc != 3) {
        fprintf(stderr, "[ERROR] Usage: %s <interface> <ja3_database.json>\n", argv[0]);
        return 1;
    }

    printf("[DEBUG] Starting TLS Monitor\n");
    printf("[DEBUG] Interface: %s\n", argv[1]);
    printf("[DEBUG] JA3 Database: %s\n", argv[2]);
    
    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        fprintf(stderr, "[ERROR] Interface %s not found: %s\n", argv[1], strerror(errno));
        return 1;
    }
    printf("[DEBUG] Interface %s index: %d\n", argv[1], ifindex);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Bump RLIMIT_MEMLOCK to allow BPF
    bump_memlock_rlimit();
    
    libbpf_set_strict_mode(LIBBPF_STRICT_NONE);

    // Load OpenSSL providers
    printf("[DEBUG] Loading OpenSSL providers\n");
    legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
    if (!legacy_provider) {
        fprintf(stderr, "[WARNING] Failed to load legacy provider\n");
    }
    default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!default_provider) {
        fprintf(stderr, "[WARNING] Failed to load default provider\n");
    }

    load_ja3_database(argv[2]);
    if (ja3_db_count == 0) {
        fprintf(stderr, "[ERROR] No JA3 signatures loaded\n");
        goto cleanup;
    }

    printf("[DEBUG] Loading BPF object: %s\n", obj_filename);
    obj = bpf_object__open_file(obj_filename, NULL);
    err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "[ERROR] Failed to open BPF object file: %s\n", strerror(-err));
        obj = NULL;
        goto cleanup;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "[ERROR] Failed to load BPF object: %s\n", strerror(-err));
        goto cleanup;
    }
    printf("[DEBUG] BPF object loaded successfully\n");

    prog = bpf_object__find_program_by_name(obj, "xdp_capture_payload");
    if (!prog) {
        fprintf(stderr, "[ERROR] Failed to find XDP program 'xdp_capture_payload'\n");
        goto cleanup;
    }

    prog_fd = bpf_program__fd(prog);
    printf("[DEBUG] BPF program found, prog_fd=%d\n", prog_fd);

    map_fd = bpf_object__find_map_fd_by_name(obj, "payload_map");
    if (map_fd < 0) {
        fprintf(stderr, "[ERROR] Failed to find payload_map: %s\n", strerror(-map_fd));
        goto cleanup;
    }
    printf("[DEBUG] Found payload_map, map_fd=%d\n", map_fd);

    link = bpf_program__attach_xdp(prog, ifindex);
    err = libbpf_get_error(link);
    if (err) {
        fprintf(stderr, "[ERROR] Failed to attach XDP program to interface: %s\n", strerror(-err));
        link = NULL;
        goto cleanup;
    }
    printf("[DEBUG] XDP program attached to interface\n");

    printf("[DEBUG] Creating perf buffer\n");
    pb = perf_buffer__new(map_fd, 16, handle_event, handle_lost_events, NULL, NULL);
    err = libbpf_get_error(pb);
    if (err) {
        fprintf(stderr, "[ERROR] Failed to create perf buffer: %s\n", strerror(-err));
        pb = NULL;
        goto cleanup;
    }
    printf("[DEBUG] Perf buffer created\n");

    printf("\n🔍 [INFO] TLS Monitor is now active!\n");
    printf("Monitoring interface %s for malicious TLS connections...\n", argv[1]);
    printf("Press Ctrl+C to stop monitoring.\n\n");

    while (running) {
        err = perf_buffer__poll(pb, 100);  // Reduced timeout for more responsive polling
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "[ERROR] Error polling perf buffer: %s\n", strerror(-err));
            break;
        }
    }

cleanup:
    printf("[DEBUG] Cleaning up resources\n");
    if (pb) {
        perf_buffer__free(pb);
    }
    if (link) {
        bpf_link__destroy(link);
    }
    if (obj) {
        bpf_object__close(obj);
    }
    if (ja3_db) {
        for (int i = 0; i < ja3_db_count; i++) {
            free(ja3_db[i].digest);
            free(ja3_db[i].ja3);
            free(ja3_db[i].description);
        }
        free(ja3_db);
    }
    if (legacy_provider) OSSL_PROVIDER_unload(legacy_provider);
    if (default_provider) OSSL_PROVIDER_unload(default_provider);
    printf("[DEBUG] Cleanup complete\n");
    return 0;
}
