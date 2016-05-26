#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>
#include "curl/curl.h"

static int num_urls = 0;
static char **urls = 0;
static CURLSH *curl_share;
static pthread_mutex_t curl_share_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t curl_share_cookie_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t curl_share_dns_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t curl_share_ssl_session_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t *openssl_mutexes = 0;
static int num_openssl_mutexes = 0;

static unsigned long openSSLIdCallback() {
	return (unsigned long)pthread_self();
}

static void openSSLLockingCallback(int mode, int n, const char* file, int line) {
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(openssl_mutexes + n);
	else
		pthread_mutex_unlock(openssl_mutexes + n);
}

static void initOpenSSLMutexes() {
	int i;
	num_openssl_mutexes = CRYPTO_num_locks();
	openssl_mutexes = malloc(num_openssl_mutexes * sizeof(pthread_mutex_t));
	for (i = 0; i < num_openssl_mutexes; ++i)
		pthread_mutex_init(openssl_mutexes + i, NULL);

	CRYPTO_set_id_callback(openSSLIdCallback);
	CRYPTO_set_locking_callback(openSSLLockingCallback);
}

static void cleanupOpenSSLMutexes() {
	int i;
	for (i = 0; i < num_openssl_mutexes; ++i)
		pthread_mutex_destroy(openssl_mutexes + i);
	free(openssl_mutexes);
}

static pthread_mutex_t *curlShareGetDataMutex(curl_lock_data data) {
	switch (data) {
		case CURL_LOCK_DATA_SHARE: return &curl_share_mutex;
		case CURL_LOCK_DATA_COOKIE: return &curl_share_cookie_mutex;
		case CURL_LOCK_DATA_DNS: return &curl_share_dns_mutex;
		case CURL_LOCK_DATA_SSL_SESSION: return &curl_share_ssl_session_mutex;
		default: return 0;
	}
}

static void curlShareLockFunc(CURL *handle, curl_lock_data data, curl_lock_access access, void *userptr) {
	pthread_mutex_lock(curlShareGetDataMutex(data));
}

static void curlShareUnlockFunc(CURL *handle, curl_lock_data data, curl_lock_access access, void *userptr) {
	pthread_mutex_unlock(curlShareGetDataMutex(data));
}

static size_t curlWriteData(void *buffer, size_t size, size_t nmemb, void *userp) {
	return size * nmemb;
}

static void *fetchThread(void *arg) {
	int tnum = (int)arg;
	int i;
	srand(tnum);
	for (i = 0; i < 100; ++i) {
		CURLcode result;
		char *url = urls[rand()%num_urls];
		CURL *curl = curl_easy_init();
		curl_easy_setopt(curl, CURLOPT_SHARE, curl_share);
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteData);
		/* curl_easy_setopt(curl, CURLOPT_VERBOSE, 1); */
		result = curl_easy_perform(curl);
		curl_easy_cleanup(curl);
	}
	return 0;
}

int main(int argc, char** argv)
{
	num_urls = argc - 1;
	urls = argv + 1;

	initOpenSSLMutexes();

	curl_global_init(CURL_GLOBAL_ALL);

	curl_share = curl_share_init();
	curl_share_setopt(curl_share, CURLSHOPT_LOCKFUNC, curlShareLockFunc);
	curl_share_setopt(curl_share, CURLSHOPT_UNLOCKFUNC, curlShareUnlockFunc);
	curl_share_setopt(curl_share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
	curl_share_setopt(curl_share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
	curl_share_setopt(curl_share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);

	pthread_t threads[2];
	pthread_create(threads + 0, NULL, fetchThread, (void*)0);
	pthread_create(threads + 1, NULL, fetchThread, (void*)1);

	pthread_join(threads[1], NULL);
	pthread_join(threads[0], NULL);

	curl_share_cleanup(curl_share);
	curl_global_cleanup();

	cleanupOpenSSLMutexes();

	return 0;
}
