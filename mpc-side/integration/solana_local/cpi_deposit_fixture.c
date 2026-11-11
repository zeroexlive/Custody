/* Isolated-validator acceptance fixture only. No custody keys or algorithms.
 * Use the pinned upstream Solana C SDK to invoke a standard System Transfer,
 * with runtime PDA authorization through sol_invoke_signed.
 */
#include <solana_sdk.h>

extern uint64_t entrypoint(const uint8_t *input) {
    SolAccountInfo accounts[3];
    SolParameters params = {.ka = accounts};
    if (!sol_deserialize(input, &params, SOL_ARRAY_SIZE(accounts)) ||
        params.ka_num != 3 || params.data_len != 9) {
        return ERROR_INVALID_ARGUMENT;
    }
    const SolPubkey system_program = {{0}};
    if (!SolPubkey_same(accounts[2].key, &system_program)) {
        return ERROR_INCORRECT_PROGRAM_ID;
    }
    const uint8_t seed[] = "phase6gc-pda-deposit";
    SolSignerSeed seeds[] = {
        {seed, sizeof(seed) - 1},
        {params.data + 8, 1}
    };
    SolPubkey expected;
    if (sol_create_program_address(seeds, SOL_ARRAY_SIZE(seeds),
                                   params.program_id, &expected) != SUCCESS ||
        !SolPubkey_same(&expected, accounts[0].key)) {
        return ERROR_INVALID_ARGUMENT;
    }
    uint8_t data[12] = {2, 0, 0, 0};
    for (int i = 0; i < 8; i++) data[4 + i] = params.data[i];
    SolAccountMeta metas[] = {
        {accounts[0].key, true, true},
        {accounts[1].key, true, false}
    };
    SolInstruction instruction = {
        accounts[2].key, metas, SOL_ARRAY_SIZE(metas), data, sizeof(data)
    };
    SolSignerSeeds signer_seeds[] = {{seeds, SOL_ARRAY_SIZE(seeds)}};
    return sol_invoke_signed(&instruction, accounts, SOL_ARRAY_SIZE(accounts),
                             signer_seeds, SOL_ARRAY_SIZE(signer_seeds));
}
