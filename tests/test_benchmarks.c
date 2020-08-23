#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include <pthread.h>

#include "../src/signal_protocol.h"
#include "curve.h"
#include "session_record.h"
#include "session_state.h"
#include "session_cipher.h"
#include "session_builder.h"
#include "protocol.h"
#include "key_helper.h"
#include "test_common.h"
#include <gcrypt.h>

#define DJB_KEY_LEN 32

static signal_protocol_address alice_address = {
        "+14159998888", 12, 1
};

static signal_protocol_address bob_address = {
        "+14151231234", 12, 1
};

signal_context *global_context;
pthread_mutex_t global_mutex;
pthread_mutexattr_t global_mutex_attr;

ec_key_pair *alice_signed_pre_key;
ec_key_pair *bob_signed_pre_key;
int32_t alice_signed_pre_key_id;
int32_t bob_signed_pre_key_id;
gcry_sexp_t alice_rsa_keypair;
gcry_sexp_t bob_rsa_keypair;

int is_session_id_equal(signal_protocol_store_context *alice_store, signal_protocol_store_context *bob_store);
int current_session_version(signal_protocol_store_context *store, const signal_protocol_address *address);
session_pre_key_bundle *create_alice_pre_key_bundle(signal_protocol_store_context *store);
session_pre_key_bundle *create_bob_pre_key_bundle(signal_protocol_store_context *store);
gcry_sexp_t asymmetric_encrypt(uint8_t *binary_key, gcry_sexp_t rsa_keypair);
int asymmetric_decrypt(uint8_t **orig_binary_key, gcry_sexp_t enc_msg, gcry_sexp_t rsa_keypair);

void test_lock(void *user_data)
{
    pthread_mutex_lock(&global_mutex);
}

void test_unlock(void *user_data)
{
    pthread_mutex_unlock(&global_mutex);
}

void test_setup()
{
    int result;

    pthread_mutexattr_init(&global_mutex_attr);
    pthread_mutexattr_settype(&global_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&global_mutex, &global_mutex_attr);

    result = signal_context_create(&global_context, 0);
    ck_assert_int_eq(result, 0);
    signal_context_set_log_function(global_context, test_log);

    setup_test_crypto_provider(global_context);

    result = signal_context_set_locking_functions(global_context, test_lock, test_unlock);
    ck_assert_int_eq(result, 0);

    result = curve_generate_key_pair(global_context, &alice_signed_pre_key);
    ck_assert_int_eq(result, 0);

    result = curve_generate_key_pair(global_context, &bob_signed_pre_key);
    ck_assert_int_eq(result, 0);

    alice_signed_pre_key_id = (rand() & 0x7FFFFFFF) % PRE_KEY_MEDIUM_MAX_VALUE;
    bob_signed_pre_key_id = (rand() & 0x7FFFFFFF) % PRE_KEY_MEDIUM_MAX_VALUE;

    gcry_error_t err;

    // S expression instructing the creation of a 2048 bit RSA key
    gcry_sexp_t rsa_params;
    err = gcry_sexp_build(&rsa_params, NULL, "(genkey (rsa (nbits 4:2048)))");
    if (err) {
        fprintf(stderr, "Failed to create RSA params\n");
    }

    // Generate Alice's RSA key pair
    err = gcry_pk_genkey(&alice_rsa_keypair, rsa_params);
    if (err) {
        fprintf(stderr, "Failed to create Alice's RSA key pair\n");
    }

    // Generate Bob's RSA key pair 
    err = gcry_pk_genkey(&bob_rsa_keypair, rsa_params);
    if (err) {
        fprintf(stderr, "Failed to create Bob's RSA key pair\n");
    }
}

void test_teardown()
{
    SIGNAL_UNREF(alice_signed_pre_key);
    SIGNAL_UNREF(bob_signed_pre_key);
    signal_context_destroy(global_context);

    pthread_mutex_destroy(&global_mutex);
    pthread_mutexattr_destroy(&global_mutex_attr);
}

START_TEST(test_basic_SKEME_protocol)
{
	int iterations = 50;
    double alice_bundle_runtime_sum = 0;
    double bob_bundle_runtime_sum = 0;
    double alice_generate_ca_runtime_sum = 0;
    double bob_generate_cb_runtime_sum = 0;
    double alice_decrypt_cb_runtime_sum = 0;
    double bob_decrypt_ca_runtime_sum = 0;
    double alice_generate_shared_key_runtime_sum = 0;
    double bob_generate_shared_key_runtime_sum = 0;
    double alice_total_setup_runtime_sum = 0;
    double bob_total_setup_runtime_sum = 0;
    double alice_bundle_runtime_avg;
    double bob_bundle_runtime_avg;
    double alice_generate_ca_runtime_avg;
    double bob_generate_cb_runtime_avg;
    double alice_decrypt_cb_runtime_avg;
    double bob_decrypt_ca_runtime_avg;
    double alice_generate_shared_key_runtime_avg;
    double bob_generate_shared_key_runtime_avg;
    double alice_total_setup_runtime_avg;
    double bob_total_setup_runtime_avg;
    int i;

    for(i = 0; i < iterations; i++)
    {
    	double alice_bundle_runtime;
    	double bob_bundle_runtime;
    	double alice_generate_ca_runtime;
    	double bob_generate_cb_runtime;
    	double alice_decrypt_cb_runtime;
    	double bob_decrypt_ca_runtime;
    	double alice_generate_shared_key_runtime;
    	double bob_generate_shared_key_runtime;
    	double alice_total_setup_runtime;
    	double bob_total_setup_runtime;

	    int result = 0;

	    /* Create the data stores */
	    signal_protocol_store_context *alice_store = 0;
	    setup_test_store_context(&alice_store, global_context);
	    signal_protocol_store_context *bob_store = 0;
	    setup_test_store_context(&bob_store, global_context);

	    /* Create the pre key bundles */
	    clock_t alice_bundle_begin = clock();
	    session_pre_key_bundle *alice_pre_key_bundle =
	            create_alice_pre_key_bundle(alice_store);
	    clock_t alice_bundle_end = clock();
	    alice_bundle_runtime = (double)(alice_bundle_end - alice_bundle_begin) / CLOCKS_PER_SEC;
        alice_bundle_runtime_sum += alice_bundle_runtime;

        clock_t bob_bundle_begin = clock();
	    session_pre_key_bundle *bob_pre_key_bundle =
	            create_bob_pre_key_bundle(bob_store);
	    clock_t bob_bundle_end = clock();
	    bob_bundle_runtime = (double)(bob_bundle_end - bob_bundle_begin) / CLOCKS_PER_SEC;
        bob_bundle_runtime_sum += bob_bundle_runtime;

	    /* Create the session builders */
	    session_builder *alice_session_builder = 0;
	    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
	    ck_assert_int_eq(result, 0);

	    session_builder *bob_session_builder = 0;
	    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
	    ck_assert_int_eq(result, 0);
	    
	    clock_t alice_generate_ca_begin = clock();
	    /* Alice creates kA */
	    uint8_t *alice_kA = malloc(32);
	    result = signal_protocol_key_helper_generate_binary_key(&alice_kA, global_context);
	    ck_assert_int_eq(result, 0);   

	    /* Alice creates cA */
	    gcry_sexp_t alice_cA = asymmetric_encrypt(alice_kA, bob_rsa_keypair);
	    if (alice_cA == NULL) fprintf(stderr, "alice_cA not created properly");
	    clock_t alice_generate_ca_end = clock();
	    alice_generate_ca_runtime = (double)(alice_generate_ca_end - alice_generate_ca_begin) / CLOCKS_PER_SEC;
        alice_generate_ca_runtime_sum += alice_generate_ca_runtime;
	    
	    clock_t bob_generate_cb_begin = clock();
	    /* Bob creates kB */
	    uint8_t *bob_kB = malloc(32);
	    result = signal_protocol_key_helper_generate_binary_key(&bob_kB, global_context);
	    ck_assert_int_eq(result, 0);    

	    /* Bob creates cB */
	    gcry_sexp_t bob_cB = asymmetric_encrypt(bob_kB, alice_rsa_keypair);
	    if (bob_cB == NULL) fprintf(stderr, "bob_cB not created properly");
	    clock_t bob_generate_cb_end = clock();
	    bob_generate_cb_runtime = (double)(bob_generate_cb_end - bob_generate_cb_begin) / CLOCKS_PER_SEC;
        bob_generate_cb_runtime_sum += bob_generate_cb_runtime;

        clock_t bob_decrypt_ca_begin = clock();
	    /* Bob decrypts cA to get kA */
	    uint8_t *decrypted_cA = 0;
	    result = asymmetric_decrypt(&decrypted_cA, alice_cA, bob_rsa_keypair);
	    ck_assert_int_eq(result, 0);
	    clock_t bob_decrypt_ca_end = clock();
	    bob_decrypt_ca_runtime = (double)(bob_decrypt_ca_end - bob_decrypt_ca_begin) / CLOCKS_PER_SEC;
        bob_decrypt_ca_runtime_sum += bob_decrypt_ca_runtime;

	    clock_t alice_decrypt_cb_begin = clock();
	    /* Alice decrypts cB to get kB */
	    uint8_t *decrypted_cB = 0;
	    result = asymmetric_decrypt(&decrypted_cB, bob_cB, alice_rsa_keypair);
	    ck_assert_int_eq(result, 0);
	    clock_t alice_decrypt_cb_end = clock();
	    alice_decrypt_cb_runtime = (double)(alice_decrypt_cb_end - alice_decrypt_cb_begin) / CLOCKS_PER_SEC;
        alice_decrypt_cb_runtime_sum += alice_decrypt_cb_runtime;

	    /* Verify that the binary keys were decrypted correctly */
	    ck_assert_int_eq(memcmp(bob_kB, decrypted_cB, DJB_KEY_LEN), 0);
	    ck_assert_int_eq(memcmp(alice_kA, decrypted_cA, DJB_KEY_LEN), 0);
	    
	    clock_t alice_generate_shared_key_begin = clock();
	    /* Create the session ciphers */
	    session_cipher *alice_session_cipher = 0;
	    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
	    ck_assert_int_eq(result, 0);
	    clock_t alice_generate_shared_key_end = clock();
	    alice_generate_shared_key_runtime = (double)(alice_generate_shared_key_end - alice_generate_shared_key_begin) / CLOCKS_PER_SEC;
        alice_generate_shared_key_runtime_sum += alice_generate_shared_key_runtime;

        clock_t bob_generate_shared_key_begin = clock();
	    session_cipher *bob_session_cipher = 0;
	    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
	    ck_assert_int_eq(result, 0);
	    clock_t bob_generate_shared_key_end = clock();
	    bob_generate_shared_key_runtime = (double)(bob_generate_shared_key_end - bob_generate_shared_key_begin) / CLOCKS_PER_SEC;
        bob_generate_shared_key_runtime_sum += bob_generate_shared_key_runtime;

	    /* Alice passes kA and the decrypted cB */
	    skeme_protocol_parameters *alice_params = 0;
	    result = skeme_protocol_parameters_create(&alice_params, alice_kA, decrypted_cB); 
	    ck_assert_int_eq(result, 0);

	    /* Bob passes kB and the decrypted cA */
	    skeme_protocol_parameters *bob_params = 0;
	    result = skeme_protocol_parameters_create(&bob_params, decrypted_cA, bob_kB); 
	    ck_assert_int_eq(result, 0);

	    /* Process the pre key bundles */
	    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key_bundle, alice_params);
	    ck_assert_int_eq(result, 0);

	    result = session_builder_process_pre_key_bundle(bob_session_builder, alice_pre_key_bundle, bob_params);
	    ck_assert_int_eq(result, 0);

	    /* Encrypt a pair of messages */
	    static const char message_for_bob_data[] = "hey there";
	    size_t message_for_bob_len = sizeof(message_for_bob_data) - 1;
	    ciphertext_message *message_for_bob = 0;
	    result = session_cipher_encrypt(alice_session_cipher,
	            (uint8_t *)message_for_bob_data, message_for_bob_len,
	            &message_for_bob);
	    ck_assert_int_eq(result, 0);

	    static const char message_for_alice_data[] = "sample message";
	    size_t message_for_alice_len = sizeof(message_for_alice_data) - 1;
	    ciphertext_message *message_for_alice = 0;
	    result = session_cipher_encrypt(bob_session_cipher,
	            (uint8_t *)message_for_alice_data, message_for_alice_len,
	            &message_for_alice);
	    ck_assert_int_eq(result, 0);

	    /* Copy the messages before decrypting */
	    pre_key_signal_message *message_for_alice_copy = 0;
	    result = pre_key_signal_message_copy(&message_for_alice_copy,
	            (pre_key_signal_message *)message_for_alice, global_context);
	    ck_assert_int_eq(result, 0);

	    pre_key_signal_message *message_for_bob_copy = 0;
	    result = pre_key_signal_message_copy(&message_for_bob_copy,
	            (pre_key_signal_message *)message_for_bob, global_context);
	    ck_assert_int_eq(result, 0);

	    /* Decrypt the messages */
	    signal_buffer *alice_plaintext = 0;
	    result = session_cipher_decrypt_pre_key_signal_message(alice_session_cipher, message_for_alice_copy, 0, &alice_plaintext, alice_params);
	    ck_assert_int_eq(result, 0);

	    signal_buffer *bob_plaintext = 0;
	    result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher, message_for_bob_copy, 0, &bob_plaintext, bob_params);
	    ck_assert_int_eq(result, 0);

	    /* Verify that the messages decrypted correctly */
	    uint8_t *alice_plaintext_data = signal_buffer_data(alice_plaintext);
	    size_t alice_plaintext_len = signal_buffer_len(alice_plaintext);
	    ck_assert_int_eq(message_for_alice_len, alice_plaintext_len);
	    ck_assert_int_eq(memcmp(message_for_alice_data, alice_plaintext_data, alice_plaintext_len), 0);

	    uint8_t *bob_plaintext_data = signal_buffer_data(bob_plaintext);
	    size_t bob_plaintext_len = signal_buffer_len(bob_plaintext);
	    ck_assert_int_eq(message_for_bob_len, bob_plaintext_len);
	    ck_assert_int_eq(memcmp(message_for_bob_data, bob_plaintext_data, bob_plaintext_len), 0);

	    /* Prepare Alice's response */
	    static const char alice_response_data[] = "second message";
	    size_t alice_response_len = sizeof(alice_response_data) - 1;
	    ciphertext_message *alice_response = 0;
	    result = session_cipher_encrypt(alice_session_cipher,
	            (uint8_t *)alice_response_data, alice_response_len,
	            &alice_response);
	    ck_assert_int_eq(result, 0);

	    /* Verify response message type */
	    ck_assert_int_eq(ciphertext_message_get_type(alice_response), CIPHERTEXT_SIGNAL_TYPE);

	    /* Copy the message before decrypting */
	    signal_message *alice_response_copy = 0;
	    result = signal_message_copy(&alice_response_copy,
	            (signal_message *)alice_response, global_context);
	    ck_assert_int_eq(result, 0);

	    /* Have Bob decrypt the response */
	    signal_buffer *response_plaintext = 0;
	    result = session_cipher_decrypt_signal_message(bob_session_cipher, alice_response_copy, 0, &response_plaintext);
	    ck_assert_int_eq(result, 0);

	    /* Verify that the message decrypted correctly */
	    uint8_t *response_plaintext_data = signal_buffer_data(response_plaintext);
	    size_t response_plaintext_len = signal_buffer_len(response_plaintext);
	    ck_assert_int_eq(alice_response_len, response_plaintext_len);
	    ck_assert_int_eq(memcmp(alice_response_data, response_plaintext_data, response_plaintext_len), 0);

	    /* Prepare Bob's final message */
	    static const char final_message_data[] = "third message";
	    size_t final_message_len = sizeof(final_message_data) - 1;
	    ciphertext_message *final_message = 0;
	    result = session_cipher_encrypt(bob_session_cipher,
	            (uint8_t *)final_message_data, final_message_len,
	            &final_message);
	    ck_assert_int_eq(result, 0);

	    /* Verify final message type */
	    ck_assert_int_eq(ciphertext_message_get_type(final_message), CIPHERTEXT_SIGNAL_TYPE);

	    /* Copy the final message before decrypting */
	    signal_message *final_message_copy = 0;
	    result = signal_message_copy(&final_message_copy,
	            (signal_message *)final_message, global_context);
	    ck_assert_int_eq(result, 0);

	    /* Have Alice decrypt the final message */
	    signal_buffer *final_plaintext = 0;
	    result = session_cipher_decrypt_signal_message(alice_session_cipher, final_message_copy, 0, &final_plaintext);
	    ck_assert_int_eq(result, 0);

	    /* Verify that the final message decrypted correctly */
	    uint8_t *final_plaintext_data = signal_buffer_data(final_plaintext);
	    size_t final_plaintext_len = signal_buffer_len(final_plaintext);
	    ck_assert_int_eq(final_message_len, final_plaintext_len);
	    ck_assert_int_eq(memcmp(final_message_data, final_plaintext_data, final_plaintext_len), 0);

	    alice_total_setup_runtime = alice_bundle_runtime + alice_generate_ca_runtime + alice_decrypt_cb_runtime + alice_generate_shared_key_runtime;
	    alice_total_setup_runtime_sum += alice_total_setup_runtime;
	    bob_total_setup_runtime = bob_bundle_runtime + bob_generate_cb_runtime + bob_decrypt_ca_runtime + bob_generate_shared_key_runtime;
	    bob_total_setup_runtime_sum += bob_total_setup_runtime;

	    /* Cleanup */
	    signal_buffer_free(final_plaintext);
	    SIGNAL_UNREF(final_message_copy);
	    SIGNAL_UNREF(final_message);
	    signal_buffer_free(response_plaintext);
	    SIGNAL_UNREF(alice_response_copy);
	    SIGNAL_UNREF(alice_response);
	    signal_buffer_free(alice_plaintext);
	    signal_buffer_free(bob_plaintext);
	    SIGNAL_UNREF(message_for_alice_copy);
	    SIGNAL_UNREF(message_for_bob_copy);
	    SIGNAL_UNREF(message_for_alice);
	    SIGNAL_UNREF(message_for_bob);
	    session_cipher_free(alice_session_cipher);
	    session_cipher_free(bob_session_cipher);
	    session_builder_free(alice_session_builder);
	    session_builder_free(bob_session_builder);
	    SIGNAL_UNREF(alice_pre_key_bundle);
	    SIGNAL_UNREF(bob_pre_key_bundle);
	    signal_protocol_store_context_destroy(alice_store);
	    signal_protocol_store_context_destroy(bob_store);
	}
	alice_bundle_runtime_avg = alice_bundle_runtime_sum/iterations;
	bob_bundle_runtime_avg = bob_bundle_runtime_sum/iterations;
	alice_generate_ca_runtime_avg = alice_generate_ca_runtime_sum/iterations;
	bob_generate_cb_runtime_avg = bob_generate_cb_runtime_sum/iterations;
	alice_decrypt_cb_runtime_avg = alice_decrypt_cb_runtime_sum/iterations;
	bob_decrypt_ca_runtime_avg = bob_decrypt_ca_runtime_sum/iterations;
	alice_generate_shared_key_runtime_avg = alice_generate_shared_key_runtime_sum/iterations;
	bob_generate_shared_key_runtime_avg = bob_generate_shared_key_runtime_sum/iterations;
	alice_total_setup_runtime_avg = alice_total_setup_runtime_sum/iterations;
	bob_total_setup_runtime_avg = bob_total_setup_runtime_sum/iterations;
    printf("ITERATIONS: %i\n", iterations);
    printf("AVERAGE RUNTIMES:\n");
    printf("\talice bundle: %f seconds\n", alice_bundle_runtime_avg);
    printf("\talice generate cA: %f seconds\n", alice_generate_ca_runtime_avg);
    printf("\talice decrypt cB: %f seconds\n", alice_decrypt_cb_runtime_avg);
    printf("\talice generate shared key: %f seconds\n", alice_generate_shared_key_runtime_avg);
    printf("\talice total setup: %f seconds\n", alice_total_setup_runtime_avg);
    printf("\tbob bundle: %f seconds\n", bob_bundle_runtime_avg);
    printf("\tbob generate cB: %f seconds\n", bob_generate_cb_runtime_avg);
    printf("\tbob decrypt cA: %f seconds\n", bob_decrypt_ca_runtime_avg);
    printf("\tbob generate shared key: %f seconds\n", bob_generate_shared_key_runtime_avg);
    printf("\tbob total setup: %f seconds\n", bob_total_setup_runtime_avg);
}
END_TEST

session_pre_key_bundle *create_alice_pre_key_bundle(signal_protocol_store_context *store)
{
    int result = 0;

    ec_key_pair *alice_unsigned_pre_key = 0;
    curve_generate_key_pair(global_context, &alice_unsigned_pre_key);
    ck_assert_int_eq(result, 0);

    int alice_unsigned_pre_key_id = (rand() & 0x7FFFFFFF) % PRE_KEY_MEDIUM_MAX_VALUE;

    ratchet_identity_key_pair *alice_identity_key_pair = 0;
    result = signal_protocol_identity_get_key_pair(store, &alice_identity_key_pair);
    ck_assert_int_eq(result, 0);

    ec_public_key *alice_signed_pre_key_public = ec_key_pair_get_public(alice_signed_pre_key);

    signal_buffer *alice_signed_pre_key_public_serialized = 0;
    result = ec_public_key_serialize(&alice_signed_pre_key_public_serialized, alice_signed_pre_key_public);
    ck_assert_int_eq(result, 0);

    signal_buffer *signature = 0;
    result = curve_calculate_signature(global_context, &signature,
            ratchet_identity_key_pair_get_private(alice_identity_key_pair),
            signal_buffer_data(alice_signed_pre_key_public_serialized),
            signal_buffer_len(alice_signed_pre_key_public_serialized));
    ck_assert_int_eq(result, 0);

    session_pre_key_bundle *alice_pre_key_bundle = 0;
    result = session_pre_key_bundle_create(&alice_pre_key_bundle,
            1, 1,
            alice_unsigned_pre_key_id,
            ec_key_pair_get_public(alice_unsigned_pre_key),
            alice_signed_pre_key_id, alice_signed_pre_key_public,
            signal_buffer_data(signature), signal_buffer_len(signature),
            ratchet_identity_key_pair_get_public(alice_identity_key_pair));
    ck_assert_int_eq(result, 0);

    session_signed_pre_key *signed_pre_key_record = 0;
    result = session_signed_pre_key_create(&signed_pre_key_record,
            alice_signed_pre_key_id, time(0), alice_signed_pre_key,
            signal_buffer_data(signature), signal_buffer_len(signature));
    ck_assert_int_eq(result, 0);

    result = signal_protocol_signed_pre_key_store_key(store, signed_pre_key_record);
    ck_assert_int_eq(result, 0);

    session_pre_key *pre_key_record = 0;
    result = session_pre_key_create(&pre_key_record, alice_unsigned_pre_key_id, alice_unsigned_pre_key);
    ck_assert_int_eq(result, 0);

    result = signal_protocol_pre_key_store_key(store, pre_key_record);
    ck_assert_int_eq(result, 0);

    SIGNAL_UNREF(pre_key_record);
    SIGNAL_UNREF(signed_pre_key_record);
    SIGNAL_UNREF(alice_identity_key_pair);
    SIGNAL_UNREF(alice_unsigned_pre_key);
    signal_buffer_free(alice_signed_pre_key_public_serialized);
    signal_buffer_free(signature);

    return alice_pre_key_bundle;
}

session_pre_key_bundle *create_bob_pre_key_bundle(signal_protocol_store_context *store)
{
    int result = 0;

    ec_key_pair *bob_unsigned_pre_key = 0;
    curve_generate_key_pair(global_context, &bob_unsigned_pre_key);
    ck_assert_int_eq(result, 0);

    int bob_unsigned_pre_key_id = (rand() & 0x7FFFFFFF) % PRE_KEY_MEDIUM_MAX_VALUE;

    ratchet_identity_key_pair *bob_identity_key_pair = 0;
    result = signal_protocol_identity_get_key_pair(store, &bob_identity_key_pair);
    ck_assert_int_eq(result, 0);

    ec_public_key *bob_signed_pre_key_public = ec_key_pair_get_public(bob_signed_pre_key);

    signal_buffer *bob_signed_pre_key_public_serialized = 0;
    result = ec_public_key_serialize(&bob_signed_pre_key_public_serialized, bob_signed_pre_key_public);
    ck_assert_int_eq(result, 0);

    signal_buffer *signature = 0;
    result = curve_calculate_signature(global_context, &signature,
            ratchet_identity_key_pair_get_private(bob_identity_key_pair),
            signal_buffer_data(bob_signed_pre_key_public_serialized),
            signal_buffer_len(bob_signed_pre_key_public_serialized));
    ck_assert_int_eq(result, 0);

    session_pre_key_bundle *bob_pre_key_bundle = 0;
    result = session_pre_key_bundle_create(&bob_pre_key_bundle,
            1, 1,
            bob_unsigned_pre_key_id,
            ec_key_pair_get_public(bob_unsigned_pre_key),
            bob_signed_pre_key_id, bob_signed_pre_key_public,
            signal_buffer_data(signature), signal_buffer_len(signature),
            ratchet_identity_key_pair_get_public(bob_identity_key_pair));
    ck_assert_int_eq(result, 0);

    session_signed_pre_key *signed_pre_key_record = 0;
    result = session_signed_pre_key_create(&signed_pre_key_record,
            bob_signed_pre_key_id, time(0), bob_signed_pre_key,
            signal_buffer_data(signature), signal_buffer_len(signature));
    ck_assert_int_eq(result, 0);

    result = signal_protocol_signed_pre_key_store_key(store, signed_pre_key_record);
    ck_assert_int_eq(result, 0);

    session_pre_key *pre_key_record = 0;
    result = session_pre_key_create(&pre_key_record, bob_unsigned_pre_key_id, bob_unsigned_pre_key);
    ck_assert_int_eq(result, 0);

    result = signal_protocol_pre_key_store_key(store, pre_key_record);
    ck_assert_int_eq(result, 0);

    SIGNAL_UNREF(pre_key_record);
    SIGNAL_UNREF(signed_pre_key_record);
    SIGNAL_UNREF(bob_identity_key_pair);
    SIGNAL_UNREF(bob_unsigned_pre_key);
    signal_buffer_free(bob_signed_pre_key_public_serialized);
    signal_buffer_free(signature);

    return bob_pre_key_bundle;
}

gcry_sexp_t asymmetric_encrypt(uint8_t *binary_key, gcry_sexp_t rsa_keypair) {
    gcry_error_t err = 0;

    // Create MPI 
    gcry_mpi_t msg;
    err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, binary_key, DJB_KEY_LEN, NULL);
    if (err) {
        fprintf(stderr, "Failed to create MPI");
        return NULL;
    }    

    // Create s expression out of msg
    gcry_sexp_t data; 
    err = gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))", msg);
    if (err) {
        fprintf(stderr, "Failed to create s expression out of msg");
        return NULL;
    }

    // Get public key
    gcry_sexp_t pub_key = gcry_sexp_find_token(rsa_keypair, "public-key", 0);
    if(pub_key == NULL) {
        fprintf(stderr, "Failed to get public key");
        return NULL;
    }

    // Encrypt with public key
    gcry_sexp_t encrypted;
    err = gcry_pk_encrypt(&encrypted, data, pub_key);
    if (err) {
        fprintf(stderr, "Failed to encrypt msg");    
        return NULL;
    }    

    return encrypted;
}

int asymmetric_decrypt(uint8_t **orig_binary_key, gcry_sexp_t enc_msg, gcry_sexp_t rsa_keypair) {
    gcry_error_t err = 0;

    // Get private key
    gcry_sexp_t priv_key = gcry_sexp_find_token(rsa_keypair, "private-key", 0);
    if(priv_key == NULL) {
        fprintf(stderr, "Failed to get private key");
        return -1;
    }

    // Decrypt with private key
    gcry_sexp_t decrypted;
    err = gcry_pk_decrypt(&decrypted, enc_msg, priv_key);
    if (err) {
        fprintf(stderr, "There was an error decrypting the msg\n");
        return -1;
    }

    // Create MPI out of decrypted value
    gcry_mpi_t out_msg = gcry_sexp_nth_mpi(decrypted, 0, GCRYMPI_FMT_USG);

    // Make decrypted msg a buffer
    uint8_t *orig_key = malloc(32);
    err = gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char*)orig_key, DJB_KEY_LEN, NULL, out_msg);
    if (err) {
        fprintf(stderr, "Failed to stringify MPI");
        return -1;
    }

    *orig_binary_key = orig_key;

    return 0;
}

Suite *session_builder_suite(void)
{
    Suite *suite = suite_create("benchmarks");

    TCase *tcase = tcase_create("case");
    tcase_add_checked_fixture(tcase, test_setup, test_teardown);
    tcase_add_test(tcase, test_basic_SKEME_protocol);
    suite_add_tcase(suite, tcase);

    return suite;
}

int main(void)
{
    int number_failed;
    Suite *suite;
    SRunner *runner;

    suite = session_builder_suite();
    runner = srunner_create(suite);

    //allows for breakpoint setting in test processes
    srunner_set_fork_status(runner, CK_NOFORK);

    srunner_run_all(runner, CK_VERBOSE);
    number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}