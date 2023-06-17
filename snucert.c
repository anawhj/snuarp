/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2023 Seoul National University
 */

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <rte_cycles.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

// Global vaiables
struct timeval time_first, time_start, time_end;
int isFirst = 0;

void measureTime(const char* step) {
    if (isFirst == 0) {
		gettimeofday(&time_start, NULL);
		gettimeofday(&time_first, NULL);
        isFirst = 1;
	} else if (strcmp(step, "last") == 0) {
		gettimeofday(&time_end, NULL);
		int time = (time_end.tv_sec - time_first.tv_sec) * 1000000 +
		    (time_end.tv_usec - time_first.tv_usec);
		printf("\nTotal roundtrip time: %d us\n", time);
    } else {
		gettimeofday(&time_end, NULL);
		int time = (time_end.tv_sec - time_start.tv_sec) * 1000000.0 +
		    (time_end.tv_usec - time_start.tv_usec);
		printf("\t-> Measured time (%s): %d us\n", step, time);
		gettimeofday(&time_start, NULL);
	}
}

// RSA 서명 생성 함수
int generate_rsa_signature(const unsigned char *message, size_t message_len, const char *private_key_path, unsigned char **signature, size_t *signature_len) {
    
	// RSA 변수 생성
	RSA *rsa = NULL;
	
	// Private Key 파일 불러오기
    FILE *private_key_file = fopen(private_key_path, "r");
    if (!private_key_file) {
        printf("Failed to open private key file.\n");
        return -1;
    }

	// Private Key 파일로부터 RSA 추출
    rsa = PEM_read_RSAPrivateKey(private_key_file, NULL, NULL, NULL);
    fclose(private_key_file);
    if (!rsa) {
        printf("Failed to read private key.\n");
        return -1;
    }

	// Hash(메시지 다이제스트) 생성
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(message, message_len, digest);
    // printf("%u", digest);
	
	// 서명 변수 생성
    *signature = (unsigned char *)malloc(RSA_size(rsa));
    if (!signature) {
        printf("Failed to allocate memory for signature.\n");
        RSA_free(rsa);
        return -1;
    }

	// 서명 실행 및 할당
    unsigned int signature_length = 0;
    int result = RSA_sign(NID_sha256, digest, SHA256_DIGEST_LENGTH, *signature, &signature_length, rsa);
    if (result != 1) {
        printf("Failed to generate RSA signature.\n");
        RSA_free(rsa);
        free(*signature);
        return -1;
    }

	// 메모리 해제
    *signature_len = signature_length;
    RSA_free(rsa);
    return 0;
}

// RSA 서명 검증 함수
int verify_rsa_signature(const unsigned char *message, size_t message_len, const char *public_key_path, const unsigned char *signature, size_t signature_len) {
    
	// RSA 변수 생성
	RSA *rsa = NULL;
	
	// Public Key 파일 불러오기
    FILE *public_key_file = fopen(public_key_path, "r");
    if (!public_key_file) {
        printf("Failed to open public key file.\n");
        return -1;
    }
	
	// Public Key 파일로부터 RSA 추출
    rsa = PEM_read_RSA_PUBKEY(public_key_file, NULL, NULL, NULL);
    fclose(public_key_file);
    if (!rsa) {
        printf("Failed to read public key.\n");
        return -1;
    }

	// Hash(메시지 다이제스트) 생성
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(message, message_len, digest);

	// 서명 검증
    int result = RSA_verify(NID_sha256, digest, SHA256_DIGEST_LENGTH, signature, signature_len, rsa);
    if (result != 1) {
        printf("RSA signature verification failed.\n");
        RSA_free(rsa);
        return -1;
    }

	// 메모리 해제
    RSA_free(rsa);
    return 0;
}

X509* load_certificate(const char* cert_file_path) {
    FILE* cert_file = fopen(cert_file_path, "r");
    if (!cert_file) {
        perror("Error opening certificate file");
        return NULL;
    }

    X509* certificate = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);

    if (!certificate) {
        perror("Error loading certificate");
        return NULL;
    }

    return certificate;
}

unsigned char *signature;
size_t signature_len;
int generate_snu_certificate(const char* msg) {
    const unsigned char message[] = "1234567890123456789012345678901234567890";
    const char private_key_path[] = "./private_key.pem";

    // Make a signature
    int result = generate_rsa_signature(message, strlen((const char *)message), private_key_path, &signature, &signature_len);
	if (result != 0) {
        printf("Failed to generate RSA signature.\n");
        return -1;
    }

    // Load a certificate file
    const char *cert_file_path = "./domain.crt";
    X509 *certificate = load_certificate(cert_file_path);
    if (certificate) {
        EVP_PKEY *pkey;
        pkey = X509_get_pubkey(certificate);
        RSA *rsa_key;
        rsa_key = EVP_PKEY_get1_RSA(pkey);
    } else {
        printf("FAIL!!");
    }
    X509_free(certificate);
    return 0;
}

int verify_snu_certificate(const char* msg) {
    const unsigned char message[] = "1234567890123456789012345678901234567890";
    const char public_key_path[] = "./public_key.pem";
    
    int result = verify_rsa_signature(message, strlen((const char *)message), public_key_path, signature, signature_len);
    
    free(signature);
	// RSA 서명 검증 실패 시
	if (result != 0) {
        printf("RSA signature verification failed.\n");
        return -1;
    }

    // Load a certificate file
    const char *cert_file_path = "./domain.crt";
    X509 *certificate = load_certificate(cert_file_path);
    if (certificate) {
        EVP_PKEY *pkey;
        pkey = X509_get_pubkey(certificate);
        RSA *rsa_key;
        rsa_key = EVP_PKEY_get1_RSA(pkey);
    } else {
        printf("FAIL!!");
    }
    X509_free(certificate);
	// RAS 서명 검증 성공 문구
    printf("RSA signature verification successful.\n");
    return 0;
}
/*
void main() {
    generate_snu_certificate("abc");
}
*/