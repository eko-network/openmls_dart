// C API of push_ffi/src/lib.rs, see there for what each function does.
#ifndef OPENMLS_PUSH_H
#define OPENMLS_PUSH_H

#include <stddef.h>
#include <stdint.h>

#define OPENMLS_PUSH_STASHED 0
#define OPENMLS_PUSH_NOT_APPLICATION 1
#define OPENMLS_PUSH_ERROR -1

typedef struct OpenmlsPush OpenmlsPush;

OpenmlsPush *openmls_push_open(const char *db_path, const uint8_t *key,
                               size_t key_len, char **err);

void openmls_push_close(OpenmlsPush *push);

int32_t openmls_push_receive(OpenmlsPush *push, const uint8_t *message,
                             size_t message_len, const char *stash_id,
                             uint8_t **plaintext, size_t *plaintext_len,
                             uint8_t **group_id, size_t *group_id_len,
                             char **err);

void openmls_push_free_bytes(uint8_t *bytes, size_t len);

void openmls_push_free_string(char *string);

#endif
