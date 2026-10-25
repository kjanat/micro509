/* micro509's resumable, single-threaded bridge to the unmodified reference implementation. */
#include <stdlib.h>
#include "src/core.h"

static argon2_context context;
static argon2_instance_t instance;
static argon2_position_t position;

int begin(uint8_t *password, uint32_t password_len, uint8_t *salt, uint32_t salt_len,
          uint8_t *secret, uint32_t secret_len, uint8_t *ad, uint32_t ad_len,
          uint8_t *output, uint32_t output_len, uint32_t memory, uint32_t passes,
          uint32_t lanes, uint32_t version, uint32_t type) {
    context = (argon2_context){
        .out = output, .outlen = output_len, .pwd = password, .pwdlen = password_len,
        .salt = salt, .saltlen = salt_len, .secret = secret, .secretlen = secret_len,
        .ad = ad, .adlen = ad_len, .t_cost = passes, .m_cost = memory,
        .lanes = lanes, .threads = 1, .version = version,
        .flags = ARGON2_FLAG_CLEAR_PASSWORD | ARGON2_FLAG_CLEAR_SECRET
    };
    int result = validate_inputs(&context);
    if (result != ARGON2_OK) return result;
    if (type != Argon2_d && type != Argon2_id) return ARGON2_INCORRECT_TYPE;
    if (version != ARGON2_VERSION_10 && version != ARGON2_VERSION_13)
        return ARGON2_INCORRECT_PARAMETER;
    uint32_t segment = memory / (lanes * ARGON2_SYNC_POINTS);
    instance = (argon2_instance_t){
        .version = version, .passes = passes,
        .memory_blocks = segment * lanes * ARGON2_SYNC_POINTS,
        .segment_length = segment, .lane_length = segment * ARGON2_SYNC_POINTS,
        .lanes = lanes, .threads = 1, .type = type
    };
    position = (argon2_position_t){0};
    return initialize(&instance, &context);
}

/* A segment is the reference implementation's unit of work. Lanes are executed
 * serially, preserving the synchronization points and exact p-lane output. */
int step(void) {
    if (position.pass >= instance.passes) return 0;
    fill_segment(&instance, position);
    if (++position.lane == instance.lanes) {
        position.lane = 0;
        if (++position.slice == ARGON2_SYNC_POINTS) {
            position.slice = 0;
            ++position.pass;
        }
    }
    return position.pass < instance.passes;
}

void finish(void) { finalize(&context, &instance); }
