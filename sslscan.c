#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <pthread.h>

char *host_name = NULL;
static pthread_mutex_t *ssl_lock = NULL;
int running_threads = 0;

void locking_function(int mode, int type, char *file, int line)
{
    if (mode & CRYPTO_LOCK){
        pthread_mutex_lock(&(ssl_lock[type]));
    }else{
        pthread_mutex_unlock(&(ssl_lock[type]));
    }
}

unsigned long id_function(void)
{
    unsigned long ret;
    
    ret=(unsigned long)pthread_self();
    return(ret);
}

int create_ssl_lock(void)
{
    int i;
    ssl_lock = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    if (!ssl_lock)
        return -1;
    
    for (i =0 ; i < CRYPTO_num_locks(); i++){
        pthread_mutex_init(&(ssl_lock[i]), NULL);
    }
    CRYPTO_set_id_callback((unsigned long (*)())id_function);

    CRYPTO_set_locking_callback((void (*)())locking_function);
    return 0;
}


static inline uint32_t ip2int(char *ip){
    uint32_t result;
    char *p;
    p = strtok(ip, ".");
    if(!p) return 0;
    result = atoi(p)*16777216;
    p = strtok(NULL, ".");
    if(!p) return 0;
    result += atoi(p)*65536;
    p = strtok(NULL, ".");
    if(!p) return 0;
    result += atoi(p)*256;
    p = strtok(NULL, ".");
    if(!p) return 0;
    result += atoi(p);
    return result;
}


void *findIP(void *IP){
    running_threads++;
    uint32_t ip = *(uint32_t *)IP;

    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    char ipstr[20];
    sprintf(ipstr,"%d.%d.%d.%d:443",bytes[3], bytes[2], bytes[1], bytes[0]);
    char *ip_str = &ipstr[0];
    long res = 1;
    
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
    SSL_CTX_set_timeout (ctx, 3);
    SSL *ssl = NULL;
    
    BIO* bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(bio, &ssl);
    SSL_set_tlsext_host_name(ssl,host_name);
    BIO_set_conn_hostname(bio, ip_str);
    BIO_set_ssl_renegotiate_timeout(bio,3);
    res = BIO_do_connect(bio);
    if(!(1 == res)) goto end;
    res = BIO_do_handshake(bio);
    if(!(1 == res)) goto end;
    X509* cert = SSL_get_peer_certificate(ssl);
    if(cert){
        char *saveptr;
        char *certline;
        char *certname = cert->name;
        
        for (certline = strtok_r(certname, "/", &saveptr);
             certline;
             certline = strtok_r(NULL, "/", &saveptr))
        {
            char *common_name = strstr(certline,"CN=");
            if(common_name != NULL){
                if(strstr(certline,host_name) != NULL){
                    printf("Found server: %s\n",ip_str);
                }
            }
        }
    }
end:
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    running_threads = running_threads - 1;
    return NULL;
}

int main(int argc,char *argv[]){
    if(SSL_library_init() != 1 || create_ssl_lock()){
        printf("Unable to init openssl library");
        return -1;
    }
    host_name = argv[1];
    char *startip = argv[2];
    char *endip = argv[3];
    if(!host_name || !startip || !endip){
        printf("Usage:  ./sslscan hostname startip endip\n");
        printf("Example:./sslscan google.com 72.0.0.0 72.255.255.255\n");
        return -1;
    }
    
    uint32_t startip_int = ip2int(startip);
    uint32_t endip_int = ip2int(endip) + 1;
    uint32_t ipcount = endip_int - startip_int;
    
    if(startip_int < 1 || endip_int < 1 || ipcount < 1){
        printf("IP Address Invalid\n");
        return -1;
    }
    
    uint32_t ip_array[ipcount];
    
    uint32_t count = 0;
    
    for(uint32_t ip = startip_int;ip < endip_int;ip++){
waithread:
        if(running_threads > 50){
            sleep(1);
            goto waithread;
        }
        pthread_t t;
        ip_array[count] = ip;
        pthread_create(&t, NULL, findIP, &ip_array[count]);
        pthread_detach(t);
        count++;
    }
    pthread_exit(NULL);
    return 0;
}
