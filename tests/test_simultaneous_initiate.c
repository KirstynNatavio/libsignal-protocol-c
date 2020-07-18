#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include <pthread.h>
#include <gcrypt.h>

#include "../src/signal_protocol.h"
#include "curve.h"
#include "session_record.h"
#include "session_state.h"
#include "session_cipher.h"
#include "session_builder.h"
#include "protocol.h"
#include "key_helper.h"
#include "test_common.h"

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
gcry_sexp_t bob_new_rsa_keypair;

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

START_TEST(test_basic_simultaneous_initiate)
{
    int result = 0;

    /* Create the data stores */
    signal_protocol_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    signal_protocol_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    /* Create the pre key bundles */
    session_pre_key_bundle *alice_pre_key_bundle =
            create_alice_pre_key_bundle(alice_store);
    session_pre_key_bundle *bob_pre_key_bundle =
            create_bob_pre_key_bundle(bob_store);

    /* Create the session builders */
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_builder *bob_session_builder = 0;
    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create the session ciphers */
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Process the pre key bundles */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key_bundle, 0);
    ck_assert_int_eq(result, 0);

    result = session_builder_process_pre_key_bundle(bob_session_builder, alice_pre_key_bundle, 0);
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

    /* Verify message types */
    ck_assert_int_eq(ciphertext_message_get_type(message_for_bob), CIPHERTEXT_PREKEY_TYPE);
    ck_assert_int_eq(ciphertext_message_get_type(message_for_alice), CIPHERTEXT_PREKEY_TYPE);

    /* Verify that the session IDs are not equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

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
    result = session_cipher_decrypt_pre_key_signal_message(alice_session_cipher, message_for_alice_copy, 0, &alice_plaintext, 0);
    ck_assert_int_eq(result, 0);

    signal_buffer *bob_plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher, message_for_bob_copy, 0, &bob_plaintext, 0);
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

    /* Verify that the session versions are correct and the IDs are not equal */
    ck_assert_int_eq(current_session_version(alice_store, &bob_address), 3);
    ck_assert_int_eq(current_session_version(bob_store, &alice_address), 3);
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

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

    /* Verify that the session IDs are now equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

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

    /* Verify that the session IDs are equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

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
END_TEST

START_TEST(test_lost_simultaneous_initiate)
{
    int result = 0;

    /* Create the data stores */
    signal_protocol_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    signal_protocol_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    /* Create the pre key bundles */
    session_pre_key_bundle *alice_pre_key_bundle =
            create_alice_pre_key_bundle(alice_store);
    session_pre_key_bundle *bob_pre_key_bundle =
            create_bob_pre_key_bundle(bob_store);

    /* Create the session builders */
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_builder *bob_session_builder = 0;
    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create the session ciphers */
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Process the pre key bundles */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key_bundle, 0);
    ck_assert_int_eq(result, 0);

    result = session_builder_process_pre_key_bundle(bob_session_builder, alice_pre_key_bundle, 0);
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

    /* Verify message types */
    ck_assert_int_eq(ciphertext_message_get_type(message_for_bob), CIPHERTEXT_PREKEY_TYPE);
    ck_assert_int_eq(ciphertext_message_get_type(message_for_alice), CIPHERTEXT_PREKEY_TYPE);

    /* Verify that the session IDs are not equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

    /* Copy the message for Bob before decrypting */
    pre_key_signal_message *message_for_bob_copy = 0;
    result = pre_key_signal_message_copy(&message_for_bob_copy,
            (pre_key_signal_message *)message_for_bob, global_context);
    ck_assert_int_eq(result, 0);

    /* Decrypt the message */
    signal_buffer *bob_plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher, message_for_bob_copy, 0, &bob_plaintext, 0);
    ck_assert_int_eq(result, 0);

    /* Verify that the message decrypted correctly */
    uint8_t *bob_plaintext_data = signal_buffer_data(bob_plaintext);
    size_t bob_plaintext_len = signal_buffer_len(bob_plaintext);
    ck_assert_int_eq(message_for_bob_len, bob_plaintext_len);
    ck_assert_int_eq(memcmp(message_for_bob_data, bob_plaintext_data, bob_plaintext_len), 0);

    /* Verify that the session version is correct */
    ck_assert_int_eq(current_session_version(bob_store, &alice_address), 3);

    /* Prepare Alice's response */
    static const char alice_response_data[] = "second message";
    size_t alice_response_len = sizeof(alice_response_data) - 1;
    ciphertext_message *alice_response = 0;
    result = session_cipher_encrypt(alice_session_cipher,
            (uint8_t *)alice_response_data, alice_response_len,
            &alice_response);
    ck_assert_int_eq(result, 0);

    /* Verify response message type */
    ck_assert_int_eq(ciphertext_message_get_type(alice_response), CIPHERTEXT_PREKEY_TYPE);

    /* Copy the message before decrypting */
    pre_key_signal_message *alice_response_copy = 0;
    result = pre_key_signal_message_copy(&alice_response_copy,
            (pre_key_signal_message *)alice_response, global_context);
    ck_assert_int_eq(result, 0);

    /* Have Bob decrypt the response */
    signal_buffer *response_plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher, alice_response_copy, 0, &response_plaintext, 0);
    ck_assert_int_eq(result, 0);

    /* Verify that the message decrypted correctly */
    uint8_t *response_plaintext_data = signal_buffer_data(response_plaintext);
    size_t response_plaintext_len = signal_buffer_len(response_plaintext);
    ck_assert_int_eq(alice_response_len, response_plaintext_len);
    ck_assert_int_eq(memcmp(alice_response_data, response_plaintext_data, response_plaintext_len), 0);

    /* Verify that the session IDs are now equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

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

    /* Verify that the session IDs are equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

    /* Cleanup */
    signal_buffer_free(final_plaintext);
    SIGNAL_UNREF(final_message_copy);
    SIGNAL_UNREF(final_message);
    signal_buffer_free(response_plaintext);
    SIGNAL_UNREF(alice_response_copy);
    SIGNAL_UNREF(alice_response);
    signal_buffer_free(bob_plaintext);
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
END_TEST

START_TEST(test_simultaneous_initiate_lost_message)
{
    int result = 0;

    /* Create the data stores */
    signal_protocol_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    signal_protocol_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    /* Create the pre key bundles */
    session_pre_key_bundle *alice_pre_key_bundle =
            create_alice_pre_key_bundle(alice_store);
    session_pre_key_bundle *bob_pre_key_bundle =
            create_bob_pre_key_bundle(bob_store);

    /* Create the session builders */
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_builder *bob_session_builder = 0;
    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create the session ciphers */
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Process the pre key bundles */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key_bundle, 0);
    ck_assert_int_eq(result, 0);

    result = session_builder_process_pre_key_bundle(bob_session_builder, alice_pre_key_bundle, 0);
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

    /* Verify message types */
    ck_assert_int_eq(ciphertext_message_get_type(message_for_bob), CIPHERTEXT_PREKEY_TYPE);
    ck_assert_int_eq(ciphertext_message_get_type(message_for_alice), CIPHERTEXT_PREKEY_TYPE);

    /* Verify that the session IDs are not equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

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
    result = session_cipher_decrypt_pre_key_signal_message(alice_session_cipher, message_for_alice_copy, 0, &alice_plaintext, 0);
    ck_assert_int_eq(result, 0);

    signal_buffer *bob_plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher, message_for_bob_copy, 0, &bob_plaintext, 0);
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

    /* Verify that the session versions are correct and the IDs are not equal */
    ck_assert_int_eq(current_session_version(alice_store, &bob_address), 3);
    ck_assert_int_eq(current_session_version(bob_store, &alice_address), 3);
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

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

    /*
     * Intentionally skip Bob decrypting the response, and continue
     * with the rest of the test.
     */

    /* Verify that the session IDs are not equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

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

    /* Verify that the session IDs are equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

    /* Cleanup */
    signal_buffer_free(final_plaintext);
    SIGNAL_UNREF(final_message_copy);
    SIGNAL_UNREF(final_message);
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
END_TEST

START_TEST(test_simultaneous_initiate_repeated_messages)
{
    int result = 0;

    /* Create the data stores */
    signal_protocol_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    signal_protocol_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    /* Create the pre key bundles */
    session_pre_key_bundle *alice_pre_key_bundle =
            create_alice_pre_key_bundle(alice_store);
    session_pre_key_bundle *bob_pre_key_bundle =
            create_bob_pre_key_bundle(bob_store);

    /* Create the session builders */
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_builder *bob_session_builder = 0;
    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create the session ciphers */
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Process the pre key bundles */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key_bundle, 0);
    ck_assert_int_eq(result, 0);

    result = session_builder_process_pre_key_bundle(bob_session_builder, alice_pre_key_bundle, 0);
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

    /* Verify message types */
    ck_assert_int_eq(ciphertext_message_get_type(message_for_bob), CIPHERTEXT_PREKEY_TYPE);
    ck_assert_int_eq(ciphertext_message_get_type(message_for_alice), CIPHERTEXT_PREKEY_TYPE);

    /* Verify that the session IDs are not equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

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
    result = session_cipher_decrypt_pre_key_signal_message(alice_session_cipher, message_for_alice_copy, 0, &alice_plaintext, 0);
    ck_assert_int_eq(result, 0);

    signal_buffer *bob_plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher, message_for_bob_copy, 0, &bob_plaintext, 0);
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

    /* Verify that the session versions are correct and the IDs are not equal */
    ck_assert_int_eq(current_session_version(alice_store, &bob_address), 3);
    ck_assert_int_eq(current_session_version(bob_store, &alice_address), 3);
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

    int i;
    for(i = 0; i < 50; i++) {
        fprintf(stderr, "Simultaneous initiate tests, iteration: %d\n", i);

        /* Encrypt a pair of messages */
        static const char message_for_bob_repeat_data[] = "hey there";
        size_t message_for_bob_repeat_len = sizeof(message_for_bob_repeat_data) - 1;
        ciphertext_message *message_for_bob_repeat = 0;
        result = session_cipher_encrypt(alice_session_cipher,
                (uint8_t *)message_for_bob_repeat_data, message_for_bob_repeat_len,
                &message_for_bob_repeat);
        ck_assert_int_eq(result, 0);

        static const char message_for_alice_repeat_data[] = "sample message";
        size_t message_for_alice_repeat_len = sizeof(message_for_alice_repeat_data) - 1;
        ciphertext_message *message_for_alice_repeat = 0;
        result = session_cipher_encrypt(bob_session_cipher,
                (uint8_t *)message_for_alice_repeat_data, message_for_alice_repeat_len,
                &message_for_alice_repeat);
        ck_assert_int_eq(result, 0);

        /* Verify message types */
        ck_assert_int_eq(ciphertext_message_get_type(message_for_bob_repeat), CIPHERTEXT_SIGNAL_TYPE);
        ck_assert_int_eq(ciphertext_message_get_type(message_for_alice_repeat), CIPHERTEXT_SIGNAL_TYPE);

        /* Verify that the session IDs are not equal */
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Copy the messages before decrypting */
        signal_message *message_for_alice_repeat_copy = 0;
        result = signal_message_copy(&message_for_alice_repeat_copy,
                (signal_message *)message_for_alice_repeat, global_context);
        ck_assert_int_eq(result, 0);

        signal_message *message_for_bob_repeat_copy = 0;
        result = signal_message_copy(&message_for_bob_repeat_copy,
                (signal_message *)message_for_bob_repeat, global_context);
        ck_assert_int_eq(result, 0);

        /* Decrypt the messages */
        signal_buffer *alice_repeat_plaintext = 0;
        result = session_cipher_decrypt_signal_message(alice_session_cipher, message_for_alice_repeat_copy, 0, &alice_repeat_plaintext);
        ck_assert_int_eq(result, 0);

        signal_buffer *bob_repeat_plaintext = 0;
        result = session_cipher_decrypt_signal_message(bob_session_cipher, message_for_bob_repeat_copy, 0, &bob_repeat_plaintext);
        ck_assert_int_eq(result, 0);

        /* Verify that the messages decrypted correctly */
        uint8_t *alice_repeat_plaintext_data = signal_buffer_data(alice_repeat_plaintext);
        size_t alice_repeat_plaintext_len = signal_buffer_len(alice_repeat_plaintext);
        ck_assert_int_eq(message_for_alice_repeat_len, alice_repeat_plaintext_len);
        ck_assert_int_eq(memcmp(message_for_alice_repeat_data, alice_repeat_plaintext_data, alice_repeat_plaintext_len), 0);

        uint8_t *bob_repeat_plaintext_data = signal_buffer_data(bob_repeat_plaintext);
        size_t bob_repeat_plaintext_len = signal_buffer_len(bob_repeat_plaintext);
        ck_assert_int_eq(message_for_bob_repeat_len, bob_repeat_plaintext_len);
        ck_assert_int_eq(memcmp(message_for_bob_repeat_data, bob_repeat_plaintext_data, bob_repeat_plaintext_len), 0);

        /* Verify that the session IDs are not equal */
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Cleanup */
        signal_buffer_free(bob_repeat_plaintext);
        signal_buffer_free(alice_repeat_plaintext);
        SIGNAL_UNREF(message_for_bob_repeat_copy);
        SIGNAL_UNREF(message_for_alice_repeat_copy);
        SIGNAL_UNREF(message_for_bob_repeat);
        SIGNAL_UNREF(message_for_alice_repeat);
    }

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

    /* Verify that the session IDs are now equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

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

    /* Verify that the session IDs are equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

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
END_TEST

START_TEST(test_repeated_simultaneous_initiate_repeated_messages)
{
    int result = 0;
    int i;

    /* Create the data stores */
    signal_protocol_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    signal_protocol_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    /* Create the session builders */
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_builder *bob_session_builder = 0;
    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create the session ciphers */
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    for(i = 0; i < 15; i++) {
        /* Create the pre key bundles */
        session_pre_key_bundle *alice_pre_key_bundle =
                create_alice_pre_key_bundle(alice_store);
        session_pre_key_bundle *bob_pre_key_bundle =
                create_bob_pre_key_bundle(bob_store);

        /* Process the pre key bundles */
        result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key_bundle, 0);
        ck_assert_int_eq(result, 0);

        result = session_builder_process_pre_key_bundle(bob_session_builder, alice_pre_key_bundle, 0);
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

        /* Verify message types */
        ck_assert_int_eq(ciphertext_message_get_type(message_for_bob), CIPHERTEXT_PREKEY_TYPE);
        ck_assert_int_eq(ciphertext_message_get_type(message_for_alice), CIPHERTEXT_PREKEY_TYPE);

        /* Verify that the session IDs are not equal */
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

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
        result = session_cipher_decrypt_pre_key_signal_message(alice_session_cipher, message_for_alice_copy, 0, &alice_plaintext, 0);
        ck_assert_int_eq(result, 0);

        signal_buffer *bob_plaintext = 0;
        result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher, message_for_bob_copy, 0, &bob_plaintext, 0);
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

        /* Verify that the session versions are correct and the IDs are not equal */
        ck_assert_int_eq(current_session_version(alice_store, &bob_address), 3);
        ck_assert_int_eq(current_session_version(bob_store, &alice_address), 3);
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Cleanup */
        signal_buffer_free(alice_plaintext);
        signal_buffer_free(bob_plaintext);
        SIGNAL_UNREF(message_for_alice_copy);
        SIGNAL_UNREF(message_for_bob_copy);
        SIGNAL_UNREF(message_for_alice);
        SIGNAL_UNREF(message_for_bob);
        SIGNAL_UNREF(alice_pre_key_bundle);
        SIGNAL_UNREF(bob_pre_key_bundle);
    }

    for(i = 0; i < 50; i++) {
        fprintf(stderr, "Simultaneous initiate tests, iteration: %d\n", i);

        /* Encrypt a pair of messages */
        static const char message_for_bob_repeat_data[] = "hey there";
        size_t message_for_bob_repeat_len = sizeof(message_for_bob_repeat_data) - 1;
        ciphertext_message *message_for_bob_repeat = 0;
        result = session_cipher_encrypt(alice_session_cipher,
                (uint8_t *)message_for_bob_repeat_data, message_for_bob_repeat_len,
                &message_for_bob_repeat);
        ck_assert_int_eq(result, 0);

        static const char message_for_alice_repeat_data[] = "sample message";
        size_t message_for_alice_repeat_len = sizeof(message_for_alice_repeat_data) - 1;
        ciphertext_message *message_for_alice_repeat = 0;
        result = session_cipher_encrypt(bob_session_cipher,
                (uint8_t *)message_for_alice_repeat_data, message_for_alice_repeat_len,
                &message_for_alice_repeat);
        ck_assert_int_eq(result, 0);

        /* Verify message types */
        ck_assert_int_eq(ciphertext_message_get_type(message_for_bob_repeat), CIPHERTEXT_SIGNAL_TYPE);
        ck_assert_int_eq(ciphertext_message_get_type(message_for_alice_repeat), CIPHERTEXT_SIGNAL_TYPE);

        /* Verify that the session IDs are not equal */
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Copy the messages before decrypting */
        signal_message *message_for_alice_repeat_copy = 0;
        result = signal_message_copy(&message_for_alice_repeat_copy,
                (signal_message *)message_for_alice_repeat, global_context);
        ck_assert_int_eq(result, 0);

        signal_message *message_for_bob_repeat_copy = 0;
        result = signal_message_copy(&message_for_bob_repeat_copy,
                (signal_message *)message_for_bob_repeat, global_context);
        ck_assert_int_eq(result, 0);

        /* Decrypt the messages */
        signal_buffer *alice_repeat_plaintext = 0;
        result = session_cipher_decrypt_signal_message(alice_session_cipher, message_for_alice_repeat_copy, 0, &alice_repeat_plaintext);
        ck_assert_int_eq(result, 0);

        signal_buffer *bob_repeat_plaintext = 0;
        result = session_cipher_decrypt_signal_message(bob_session_cipher, message_for_bob_repeat_copy, 0, &bob_repeat_plaintext);
        ck_assert_int_eq(result, 0);

        /* Verify that the messages decrypted correctly */
        uint8_t *alice_repeat_plaintext_data = signal_buffer_data(alice_repeat_plaintext);
        size_t alice_repeat_plaintext_len = signal_buffer_len(alice_repeat_plaintext);
        ck_assert_int_eq(message_for_alice_repeat_len, alice_repeat_plaintext_len);
        ck_assert_int_eq(memcmp(message_for_alice_repeat_data, alice_repeat_plaintext_data, alice_repeat_plaintext_len), 0);

        uint8_t *bob_repeat_plaintext_data = signal_buffer_data(bob_repeat_plaintext);
        size_t bob_repeat_plaintext_len = signal_buffer_len(bob_repeat_plaintext);
        ck_assert_int_eq(message_for_bob_repeat_len, bob_repeat_plaintext_len);
        ck_assert_int_eq(memcmp(message_for_bob_repeat_data, bob_repeat_plaintext_data, bob_repeat_plaintext_len), 0);

        /* Verify that the session IDs are not equal */
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Cleanup */
        signal_buffer_free(bob_repeat_plaintext);
        signal_buffer_free(alice_repeat_plaintext);
        SIGNAL_UNREF(message_for_bob_repeat_copy);
        SIGNAL_UNREF(message_for_alice_repeat_copy);
        SIGNAL_UNREF(message_for_bob_repeat);
        SIGNAL_UNREF(message_for_alice_repeat);
    }

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

    /* Verify that the session IDs are now equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

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

    /* Verify that the session IDs are equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

    /* Cleanup */
    signal_buffer_free(final_plaintext);
    SIGNAL_UNREF(final_message_copy);
    SIGNAL_UNREF(final_message);
    signal_buffer_free(response_plaintext);
    SIGNAL_UNREF(alice_response_copy);
    SIGNAL_UNREF(alice_response);
    session_cipher_free(alice_session_cipher);
    session_cipher_free(bob_session_cipher);
    session_builder_free(alice_session_builder);
    session_builder_free(bob_session_builder);
    signal_protocol_store_context_destroy(alice_store);
    signal_protocol_store_context_destroy(bob_store);
}
END_TEST

START_TEST(test_repeated_simultaneous_initiate_lost_message_repeated_messages)
{
    int result = 0;
    int i;

    /* Create the data stores */
    signal_protocol_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    signal_protocol_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    /* Create the session builders */
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_builder *bob_session_builder = 0;
    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create the session ciphers */
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

    /* Create the pre key bundles, intentionally skipping Alice's */
    session_pre_key_bundle *bob_lost_pre_key_bundle =
            create_bob_pre_key_bundle(bob_store);

    /* Process the pre key bundles, intentionally skipping Alice's */
    result = session_builder_process_pre_key_bundle(alice_session_builder, bob_lost_pre_key_bundle, 0);
    ck_assert_int_eq(result, 0);

    /* Encrypt a pair of messages, intentionally skipping Alice's */
    static const char lost_message_for_bob_data[] = "hey there";
    size_t lost_message_for_bob_len = sizeof(lost_message_for_bob_data) - 1;
    ciphertext_message *lost_message_for_bob = 0;
    result = session_cipher_encrypt(alice_session_cipher,
            (uint8_t *)lost_message_for_bob_data, lost_message_for_bob_len,
            &lost_message_for_bob);
    ck_assert_int_eq(result, 0);

    for(i = 0; i < 15; i++) {
        /* Create the pre key bundles */
        session_pre_key_bundle *alice_pre_key_bundle =
                create_alice_pre_key_bundle(alice_store);
        session_pre_key_bundle *bob_pre_key_bundle =
                create_bob_pre_key_bundle(bob_store);

        /* Process the pre key bundles */
        result = session_builder_process_pre_key_bundle(alice_session_builder, bob_pre_key_bundle, 0);
        ck_assert_int_eq(result, 0);

        result = session_builder_process_pre_key_bundle(bob_session_builder, alice_pre_key_bundle, 0);
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

        /* Verify message types */
        ck_assert_int_eq(ciphertext_message_get_type(message_for_bob), CIPHERTEXT_PREKEY_TYPE);
        ck_assert_int_eq(ciphertext_message_get_type(message_for_alice), CIPHERTEXT_PREKEY_TYPE);

        /* Verify that the session IDs are not equal */
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

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
        result = session_cipher_decrypt_pre_key_signal_message(alice_session_cipher, message_for_alice_copy, 0, &alice_plaintext, 0);
        ck_assert_int_eq(result, 0);

        signal_buffer *bob_plaintext = 0;
        result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher, message_for_bob_copy, 0, &bob_plaintext, 0);
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

        /* Verify that the session versions are correct and the IDs are not equal */
        ck_assert_int_eq(current_session_version(alice_store, &bob_address), 3);
        ck_assert_int_eq(current_session_version(bob_store, &alice_address), 3);
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Cleanup */
        signal_buffer_free(alice_plaintext);
        signal_buffer_free(bob_plaintext);
        SIGNAL_UNREF(message_for_alice_copy);
        SIGNAL_UNREF(message_for_bob_copy);
        SIGNAL_UNREF(message_for_alice);
        SIGNAL_UNREF(message_for_bob);
        SIGNAL_UNREF(alice_pre_key_bundle);
        SIGNAL_UNREF(bob_pre_key_bundle);
    }

    for(i = 0; i < 50; i++) {
        fprintf(stderr, "Simultaneous initiate tests, iteration: %d\n", i);

        /* Encrypt a pair of messages */
        static const char message_for_bob_repeat_data[] = "hey there";
        size_t message_for_bob_repeat_len = sizeof(message_for_bob_repeat_data) - 1;
        ciphertext_message *message_for_bob_repeat = 0;
        result = session_cipher_encrypt(alice_session_cipher,
                (uint8_t *)message_for_bob_repeat_data, message_for_bob_repeat_len,
                &message_for_bob_repeat);
        ck_assert_int_eq(result, 0);

        static const char message_for_alice_repeat_data[] = "sample message";
        size_t message_for_alice_repeat_len = sizeof(message_for_alice_repeat_data) - 1;
        ciphertext_message *message_for_alice_repeat = 0;
        result = session_cipher_encrypt(bob_session_cipher,
                (uint8_t *)message_for_alice_repeat_data, message_for_alice_repeat_len,
                &message_for_alice_repeat);
        ck_assert_int_eq(result, 0);

        /* Verify message types */
        ck_assert_int_eq(ciphertext_message_get_type(message_for_bob_repeat), CIPHERTEXT_SIGNAL_TYPE);
        ck_assert_int_eq(ciphertext_message_get_type(message_for_alice_repeat), CIPHERTEXT_SIGNAL_TYPE);

        /* Verify that the session IDs are not equal */
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Copy the messages before decrypting */
        signal_message *message_for_alice_repeat_copy = 0;
        result = signal_message_copy(&message_for_alice_repeat_copy,
                (signal_message *)message_for_alice_repeat, global_context);
        ck_assert_int_eq(result, 0);

        signal_message *message_for_bob_repeat_copy = 0;
        result = signal_message_copy(&message_for_bob_repeat_copy,
                (signal_message *)message_for_bob_repeat, global_context);
        ck_assert_int_eq(result, 0);

        /* Decrypt the messages */
        signal_buffer *alice_repeat_plaintext = 0;
        result = session_cipher_decrypt_signal_message(alice_session_cipher, message_for_alice_repeat_copy, 0, &alice_repeat_plaintext);
        ck_assert_int_eq(result, 0);

        signal_buffer *bob_repeat_plaintext = 0;
        result = session_cipher_decrypt_signal_message(bob_session_cipher, message_for_bob_repeat_copy, 0, &bob_repeat_plaintext);
        ck_assert_int_eq(result, 0);

        /* Verify that the messages decrypted correctly */
        uint8_t *alice_repeat_plaintext_data = signal_buffer_data(alice_repeat_plaintext);
        size_t alice_repeat_plaintext_len = signal_buffer_len(alice_repeat_plaintext);
        ck_assert_int_eq(message_for_alice_repeat_len, alice_repeat_plaintext_len);
        ck_assert_int_eq(memcmp(message_for_alice_repeat_data, alice_repeat_plaintext_data, alice_repeat_plaintext_len), 0);

        uint8_t *bob_repeat_plaintext_data = signal_buffer_data(bob_repeat_plaintext);
        size_t bob_repeat_plaintext_len = signal_buffer_len(bob_repeat_plaintext);
        ck_assert_int_eq(message_for_bob_repeat_len, bob_repeat_plaintext_len);
        ck_assert_int_eq(memcmp(message_for_bob_repeat_data, bob_repeat_plaintext_data, bob_repeat_plaintext_len), 0);

        /* Verify that the session IDs are not equal */
        ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

        /* Cleanup */
        signal_buffer_free(bob_repeat_plaintext);
        signal_buffer_free(alice_repeat_plaintext);
        SIGNAL_UNREF(message_for_bob_repeat_copy);
        SIGNAL_UNREF(message_for_alice_repeat_copy);
        SIGNAL_UNREF(message_for_bob_repeat);
        SIGNAL_UNREF(message_for_alice_repeat);
    }

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

    /* Verify that the session IDs are now equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

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

    /* Verify that the session IDs are equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

    /* Copy the lost message before decrypting */
    pre_key_signal_message *lost_message_for_bob_copy = 0;
    result = pre_key_signal_message_copy(&lost_message_for_bob_copy,
            (pre_key_signal_message *)lost_message_for_bob, global_context);
    ck_assert_int_eq(result, 0);

    /* Decrypt the lost message */
    signal_buffer *lost_message_for_bob_plaintext = 0;
    result = session_cipher_decrypt_pre_key_signal_message(bob_session_cipher,
            lost_message_for_bob_copy, 0, &lost_message_for_bob_plaintext, 0);
    ck_assert_int_eq(result, 0);

    /* Verify that the lost message decrypted correctly */
    uint8_t *lost_bob_plaintext_data = signal_buffer_data(lost_message_for_bob_plaintext);
    size_t lost_bob_plaintext_len = signal_buffer_len(lost_message_for_bob_plaintext);
    ck_assert_int_eq(lost_message_for_bob_len, lost_bob_plaintext_len);
    ck_assert_int_eq(memcmp(lost_message_for_bob_data, lost_bob_plaintext_data, lost_bob_plaintext_len), 0);

    /* Verify that the session IDs are not equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 0);

    /* Encrypt an unexpected final message */
    static const char blast_from_the_past_data[] = "unexpected!";
    size_t blast_from_the_past_len = sizeof(blast_from_the_past_data) - 1;
    ciphertext_message *blast_from_the_past = 0;
    result = session_cipher_encrypt(bob_session_cipher,
            (uint8_t *)blast_from_the_past_data, blast_from_the_past_len,
            &blast_from_the_past);
    ck_assert_int_eq(result, 0);

    /* Copy the unexpected message before decrypting */
    signal_message *blast_from_the_past_copy = 0;
    result = signal_message_copy(&blast_from_the_past_copy,
            (signal_message *)blast_from_the_past, global_context);
    ck_assert_int_eq(result, 0);

    /* Decrypt the unexpected message */
    signal_buffer *blast_from_the_past_plaintext = 0;
    result = session_cipher_decrypt_signal_message(alice_session_cipher,
            blast_from_the_past_copy, 0, &blast_from_the_past_plaintext);
    ck_assert_int_eq(result, 0);

    /* Verify that the unexpected message decrypted correctly */
    uint8_t *blast_from_the_past_decrypted_data = signal_buffer_data(blast_from_the_past_plaintext);
    size_t blast_from_the_past_decrypted_len = signal_buffer_len(blast_from_the_past_plaintext);
    ck_assert_int_eq(blast_from_the_past_len, blast_from_the_past_decrypted_len);
    ck_assert_int_eq(memcmp(blast_from_the_past_data, blast_from_the_past_decrypted_data, blast_from_the_past_decrypted_len), 0);

    /* Verify that the session IDs are equal */
    ck_assert_int_eq(is_session_id_equal(alice_store, bob_store), 1);

    /* Cleanup */
    signal_buffer_free(blast_from_the_past_plaintext);
    SIGNAL_UNREF(blast_from_the_past_copy);
    SIGNAL_UNREF(blast_from_the_past);
    signal_buffer_free(lost_message_for_bob_plaintext);
    SIGNAL_UNREF(lost_message_for_bob_copy);
    signal_buffer_free(final_plaintext);
    SIGNAL_UNREF(final_message_copy);
    SIGNAL_UNREF(final_message);
    signal_buffer_free(response_plaintext);
    SIGNAL_UNREF(alice_response_copy);
    SIGNAL_UNREF(alice_response);
    SIGNAL_UNREF(bob_lost_pre_key_bundle);
    SIGNAL_UNREF(lost_message_for_bob);
    session_cipher_free(alice_session_cipher);
    session_cipher_free(bob_session_cipher);
    session_builder_free(alice_session_builder);
    session_builder_free(bob_session_builder);
    signal_protocol_store_context_destroy(alice_store);
    signal_protocol_store_context_destroy(bob_store);
}
END_TEST

START_TEST(test_basic_SKEME_protocol)
{
    int result = 0;

    /* Create the data stores */
    signal_protocol_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    signal_protocol_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    /* Create the pre key bundles */
    session_pre_key_bundle *alice_pre_key_bundle =
            create_alice_pre_key_bundle(alice_store);
    session_pre_key_bundle *bob_pre_key_bundle =
            create_bob_pre_key_bundle(bob_store);

    /* Create the session builders */
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_builder *bob_session_builder = 0;
    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);
    
    /* Alice creates kA */
    uint8_t *alice_kA = malloc(32);
    result = signal_protocol_key_helper_generate_binary_key(&alice_kA, global_context);
    ck_assert_int_eq(result, 0);   

    /* Alice creates cA */
    gcry_sexp_t alice_cA = asymmetric_encrypt(alice_kA, bob_rsa_keypair);
    if (alice_cA == NULL) fprintf(stderr, "alice_cA not created properly");
    
    /* Bob creates kB */
    uint8_t *bob_kB = malloc(32);
    result = signal_protocol_key_helper_generate_binary_key(&bob_kB, global_context);
    ck_assert_int_eq(result, 0);    

    /* Bob creates cB */
    gcry_sexp_t bob_cB = asymmetric_encrypt(bob_kB, alice_rsa_keypair);
    if (bob_cB == NULL) fprintf(stderr, "bob_cB not created properly");

    /* Bob decrypts cA to get kA */
    uint8_t *decrypted_cA = 0;
    result = asymmetric_decrypt(&decrypted_cA, alice_cA, bob_rsa_keypair);
    ck_assert_int_eq(result, 0);

    /* Alice decrypts cB to get kB */
    uint8_t *decrypted_cB = 0;
    result = asymmetric_decrypt(&decrypted_cB, bob_cB, alice_rsa_keypair);
    ck_assert_int_eq(result, 0);

    /* Verify that the binary keys were decrypted correctly */
    ck_assert_int_eq(memcmp(bob_kB, decrypted_cB, DJB_KEY_LEN), 0);
    ck_assert_int_eq(memcmp(alice_kA, decrypted_cA, DJB_KEY_LEN), 0);
    
    /* Create the session ciphers */
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

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
END_TEST

START_TEST(test_asym_encryption)
{
    int result = 0;

    /* Create the data stores */
    signal_protocol_store_context *alice_store = 0;
    setup_test_store_context(&alice_store, global_context);
    signal_protocol_store_context *bob_store = 0;
    setup_test_store_context(&bob_store, global_context);

    /* Create the pre key bundles */
    session_pre_key_bundle *alice_pre_key_bundle =
            create_alice_pre_key_bundle(alice_store);
    session_pre_key_bundle *bob_pre_key_bundle =
            create_bob_pre_key_bundle(bob_store);

    /* Create the session builders */
    session_builder *alice_session_builder = 0;
    result = session_builder_create(&alice_session_builder, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_builder *bob_session_builder = 0;
    result = session_builder_create(&bob_session_builder, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);
    
    /* Alice creates kA */
    uint8_t *alice_kA = malloc(32);
    result = signal_protocol_key_helper_generate_binary_key(&alice_kA, global_context);
    ck_assert_int_eq(result, 0);   

    /* Alice creates cA */
    gcry_sexp_t alice_cA = asymmetric_encrypt(alice_kA, bob_rsa_keypair);
    if (alice_cA == NULL) fprintf(stderr, "alice_cA not created properly");
    
    /* Bob creates kB */
    uint8_t *bob_kB = malloc(32);
    result = signal_protocol_key_helper_generate_binary_key(&bob_kB, global_context);
    ck_assert_int_eq(result, 0);    

    /* Bob creates cB */
    gcry_sexp_t bob_cB = asymmetric_encrypt(bob_kB, alice_rsa_keypair);
    if (bob_cB == NULL) fprintf(stderr, "bob_cB not created properly");

    
    // S expression instructing the creation of a 2048 bit RSA key
    gcry_error_t err;
    gcry_sexp_t new_rsa_params;
    err = gcry_sexp_build(&new_rsa_params, NULL, "(genkey (rsa (nbits 4:2048)))");
    if (err) {
        fprintf(stderr, "Failed to create RSA params\n");
    }

    // Generate Bob's new RSA key pair 
    err = gcry_pk_genkey(&bob_new_rsa_keypair, new_rsa_params);
    if (err) {
        fprintf(stderr, "Failed to create Bob's RSA key pair\n");
    }

    /* Bob tries to decrypt cA to get kA with a new RSA keypair*/
    uint8_t *decrypted_cA = 0;
    result = asymmetric_decrypt(&decrypted_cA, alice_cA, bob_new_rsa_keypair);
    ck_assert_int_eq(result, -1);
     printf("\nBob failed to decrypt cA with a new key! Continuing...\n");

    /* Bob decrypts cA to get kA */
    result = asymmetric_decrypt(&decrypted_cA, alice_cA, bob_rsa_keypair);
    ck_assert_int_eq(result, 0);

    /* Alice decrypts cB to get kB */
    uint8_t *decrypted_cB = 0;
    result = asymmetric_decrypt(&decrypted_cB, bob_cB, alice_rsa_keypair);
    ck_assert_int_eq(result, 0);

    /* Verify that the binary keys were decrypted correctly */
    ck_assert_int_eq(memcmp(bob_kB, decrypted_cB, DJB_KEY_LEN), 0);
    ck_assert_int_eq(memcmp(alice_kA, decrypted_cA, DJB_KEY_LEN), 0);
    
    /* Create the session ciphers */
    session_cipher *alice_session_cipher = 0;
    result = session_cipher_create(&alice_session_cipher, alice_store, &bob_address, global_context);
    ck_assert_int_eq(result, 0);

    session_cipher *bob_session_cipher = 0;
    result = session_cipher_create(&bob_session_cipher, bob_store, &alice_address, global_context);
    ck_assert_int_eq(result, 0);

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
END_TEST

int is_session_id_equal(signal_protocol_store_context *alice_store, signal_protocol_store_context *bob_store)
{
    int result = 0;
    session_record *alice_store_record = 0;
    session_record *bob_store_record = 0;
    ec_public_key *alice_store_alice_base_key = 0;
    ec_public_key *bob_store_alice_base_key = 0;

    result = signal_protocol_session_load_session(alice_store, &alice_store_record, &bob_address);
    ck_assert_int_eq(result, 0);

    result = signal_protocol_session_load_session(bob_store, &bob_store_record, &alice_address);
    ck_assert_int_eq(result, 0);

    alice_store_alice_base_key =
            session_state_get_alice_base_key(session_record_get_state(alice_store_record));
    bob_store_alice_base_key =
            session_state_get_alice_base_key(session_record_get_state(bob_store_record));

    if(ec_public_key_compare(alice_store_alice_base_key, bob_store_alice_base_key) == 0) {
        result = 1;
    }
    else {
        result = 0;
    }

    SIGNAL_UNREF(alice_store_record);
    SIGNAL_UNREF(bob_store_record);
    return result;
}

int current_session_version(signal_protocol_store_context *store, const signal_protocol_address *address)
{
    int result = 0;
    session_record *record = 0;
    session_state *state = 0;

    result = signal_protocol_session_load_session(store, &record, address);
    ck_assert_int_eq(result, 0);

    state = session_record_get_state(record);

    result = session_state_get_session_version(state);

    SIGNAL_UNREF(record);

    return result;
}

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

Suite *simultaneous_initiate_suite(void)
{
    Suite *suite = suite_create("simultaneous_initiate");

    TCase *tcase = tcase_create("case");
    tcase_add_checked_fixture(tcase, test_setup, test_teardown);
    tcase_add_test(tcase, test_basic_simultaneous_initiate);
    tcase_add_test(tcase, test_lost_simultaneous_initiate);
    tcase_add_test(tcase, test_simultaneous_initiate_lost_message);
    tcase_add_test(tcase, test_simultaneous_initiate_repeated_messages);
    tcase_add_test(tcase, test_repeated_simultaneous_initiate_repeated_messages);
    tcase_add_test(tcase, test_repeated_simultaneous_initiate_lost_message_repeated_messages);
    tcase_add_test(tcase, test_basic_SKEME_protocol);
    tcase_add_test(tcase, test_asym_encryption);
    suite_add_tcase(suite, tcase);

    return suite;
}

int main(void)
{
    int number_failed;
    Suite *suite;
    SRunner *runner;

    suite = simultaneous_initiate_suite();
    runner = srunner_create(suite);

    //allows for breakpoint setting in test processes
    srunner_set_fork_status(runner, CK_NOFORK);

    srunner_run_all(runner, CK_VERBOSE);
    number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
