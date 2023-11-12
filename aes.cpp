#include <cstdio>
#include <cstring>
#include <stdexcept>

#include "aes.hpp"
#include "randombytes.hpp"

AES::AES(const KeyLength& key_length, const Mode& mode)
    : mode(mode) {
    switch (key_length) {
        case L128: {
            nk = 4;
            nr = 10;
            break;
        }
        case L192: {
            nk = 6;
            nr = 12;
            break;
        } 
        case L256: {
            nk = 8;
            nr = 14;
            break;
        }
    }
}

#ifdef QT_CORE_LIB

void AES::Encrypt(QByteArray &data, const QByteArray &key, QByteArray iv) {
    qint64 data_size = data.size();
    data.insert(0, (char*)(&data_size), sizeof(qint64));
    int additional_size = IV_SIZE - (data.size() % IV_SIZE);
    data.resize(data.size() + (additional_size == IV_SIZE ? 0 : additional_size));
    
    if(mode == CBC || mode == CFB) {
        if(iv.isEmpty()) {
            iv = randombytes(IV_SIZE);
        } else if(iv.size() != IV_SIZE) {
            throw std::length_error("IV length must be 16");
        }
    }
    
    uchar* encrypted = Encrypt((uchar*)data.data(), data.size(), (uchar*)key.data(), (uchar*)iv.data());
    data.setRawData((char*)encrypted, data.size());
    
    if(mode == CBC || mode == CFB) data.insert(0, iv);
}

void AES::Decrypt(QByteArray &data, const QByteArray &key, QByteArray iv) {
    if(mode == CBC || mode == CFB) {
        if(iv.isEmpty()) {
            iv = data.mid(0, IV_SIZE);
            data.remove(0, IV_SIZE);
        } else if(iv.size() != IV_SIZE) {
            throw std::length_error("IV length must be 16");
        }
    }
    
    uchar* decrypted = Decrypt((uchar*)data.data(), data.size(), (uchar*)key.data(), (uchar*)iv.data());
    data.setRawData((char*)decrypted, data.size());
    qint64 data_size = *(qint64*)data.mid(0, sizeof(qint64)).data();
    data.remove(0, sizeof(qint64));
    data.resize(data_size);
}

#endif /* ifdef(QT_CORE_LIB) */

uchar* AES::Encrypt(uchar *data, uint data_size, const uchar *key, uchar *iv) {
    switch(mode) {
        case ECB: {
            return encrypt_ecb(data, data_size, key);
        }
        case CBC: {
            return encrypt_cbc(data, data_size, key, iv);
        }
        case CFB: {
            return encrypt_cfb(data, data_size, key, iv);
        }
    }
    return nullptr;
}

uchar* AES::Decrypt(uchar *data, uint data_size, const uchar *key, const uchar *iv) {
    switch(mode) {
        case ECB: {
            return decrypt_ecb(data, data_size, key);
        }
        case CBC: {
            return decrypt_cbc(data, data_size, key, iv);
        }
        case CFB: {
            return decrypt_cfb(data, data_size, key, iv);
        }
    }
    return nullptr;
}

uchar* AES::encrypt_ecb(uchar* data, uint data_length, const uchar* key) {
    check_length(data_length);
    
    uchar *encrypted  = new uchar[data_length];
    uchar *round_keys = new uchar[4 * nb * (nr + 1)];
    
    key_expansion(key, round_keys);
    
    for (uint i = 0; i < data_length; i += block_length) {
        encrypt_block(data + i, encrypted + i, round_keys);
    }
    
    delete [] round_keys;
    
    return encrypted;
}

uchar* AES::decrypt_ecb(uchar* data, uint data_length, const uchar* key) {
    check_length(data_length);
    
    uchar *decrypted  = new uchar[data_length];
    uchar *round_keys = new uchar[4 * nb * (nr + 1)];
    
    key_expansion(key, round_keys);
    
    for (uint i = 0; i < data_length; i += block_length) {
        decrypt_block(data + i, decrypted + i, round_keys);
    }
    
    delete [] round_keys;
    return decrypted;
}

uchar* AES::encrypt_cbc(uchar* data, uint data_length, const uchar* key, const uchar *iv) {
    check_length(data_length);
    
    uchar  block[block_length];
    uchar *encrypted  = new uchar[data_length];
    uchar *round_keys = new uchar[4 * nb * (nr + 1)];
    
    key_expansion(key, round_keys);
    memcpy(block, iv, block_length);
    
    for (uint i = 0; i < data_length; i += block_length) {
        xor_blocks(block, data + i, block, block_length);
        encrypt_block(block, encrypted + i, round_keys);
        memcpy(block, encrypted + i, block_length);
    }
    
    delete [] round_keys;
    
    return encrypted;
}

uchar* AES::decrypt_cbc(uchar* data, uint data_length, const uchar* key, const uchar *iv) {
    check_length(data_length);
    
    uchar  block[block_length];
    uchar *decrypted  = new uchar[data_length];
    uchar *round_keys = new uchar[4 * nb * (nr + 1)];
    
    key_expansion(key, round_keys);
    memcpy(block, iv, block_length);
    
    for (uint i = 0; i < data_length; i += block_length) {
        decrypt_block(data + i, decrypted + i, round_keys);
        xor_blocks(block, decrypted + i, decrypted + i, block_length);
        memcpy(block, data + i, block_length);
    }
    
    delete [] round_keys;
    
    return decrypted;
}

uchar* AES::encrypt_cfb(uchar* data, uint data_length, const uchar* key, const uchar *iv) {
    check_length(data_length);
    
    uchar  block[block_length];
    uchar  encrypted_block[block_length];
    uchar *encrypted  = new uchar[data_length];
    uchar *round_keys = new uchar[4 * nb * (nr + 1)];
    
    key_expansion(key, round_keys);
    memcpy(block, iv, block_length);
    
    for (uint i = 0; i < data_length; i += block_length) {
        encrypt_block(block, encrypted_block, round_keys);
        xor_blocks(data + i, encrypted_block, encrypted + i, block_length);
        memcpy(block, encrypted + i, block_length);
    }
    
    delete [] round_keys;
    
    return encrypted;
}

uchar* AES::decrypt_cfb(uchar* data, uint data_length, const uchar* key, const uchar *iv) {
    check_length(data_length);
    
    uchar  block[block_length];
    uchar  encrypted_block[block_length];
    uchar *decrypted  = new uchar[data_length];
    uchar *round_keys = new uchar[4 * nb * (nr + 1)];
    
    key_expansion(key, round_keys);
    memcpy(block, iv, block_length);
    
    for (uint i = 0; i < data_length; i += block_length) {
        encrypt_block(block, encrypted_block, round_keys);
        xor_blocks(data + i, encrypted_block, decrypted + i, block_length);
        memcpy(block, data + i, block_length);
    }
    
    delete [] round_keys;
    
    return decrypted;
}

void AES::check_length(uint length) {
    if (length % block_length != 0) {
        std::string err = "Plaintext length must be divisible by ";
        err += std::to_string(block_length);
        throw std::length_error(err);
    }
}

void AES::encrypt_block(const uchar* in, uchar* out, uchar* rkey) {
    uint  round;
    uchar state[4][nb];
    
    for (uint i = 0; i < 4; i++) {
        for (uint j = 0; j < nb; j++) {
            state[i][j] = in[i + 4 * j];
        }
    }
    
    add_round_key(state, rkey);
    
    for (round = 1; round <= nr - 1; round++) {
        sub_bytes    (state);
        shift_rows   (state);
        mix_columns  (state);
        add_round_key(state, rkey + round * 4 * nb);
    }
    
    sub_bytes    (state);
    shift_rows   (state);
    add_round_key(state, rkey + nr * 4 * nb);
    
    for (uint i = 0; i < 4; i++) {
        for (uint j = 0; j < nb; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }
}

void AES::decrypt_block(const uchar* in, uchar* out, uchar* rkey) {
    uint round;
    uchar state[4][nb];
    
    for (uint i = 0; i < 4; i++) {
        for (uint j = 0; j < nb; j++) {
            state[i][j] = in[i + 4 * j];
        }
    }
    
    add_round_key(state, rkey + nr * 4 * nb);
    
    for (round = nr - 1; round >= 1; round--) {
        inv_sub_bytes  (state);
        inv_shift_rows (state);
        add_round_key  (state, rkey + round * 4 * nb);
        inv_mix_columns(state);
    }
    
    inv_sub_bytes (state);
    inv_shift_rows(state);
    add_round_key (state, rkey);
    
    for (uint i = 0; i < 4; i++) {
        for (uint j = 0; j < nb; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }
}

void AES::sub_bytes(uchar state[4][nb]) {
    uchar t;
    
    for (uint i = 0; i < 4; i++) {
        for (uint j = 0; j < nb; j++) {
            t = state[i][j];
            state[i][j] = sbox[t / 16][t % 16];
        }
    }
}

void AES::shift_row(uchar state[4][nb], uint i, uint n) {
    uchar tmp[nb];
    for (uint j = 0; j < nb; j++) {
        tmp[j] = state[i][(j + n) % nb];
    }
    memcpy(state[i], tmp, nb * sizeof(uchar));
}

void AES::shift_rows(uchar state[4][nb]) {
    shift_row(state, 1, 1);
    shift_row(state, 2, 2);
    shift_row(state, 3, 3);
}

uchar AES::xtime(uchar b) {
    return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}

void AES::mix_columns(uchar state[4][nb]) {
    uchar temp_state[4][nb];
    
    for (size_t i = 0; i < 4; ++i) {
        memset(temp_state[i], 0, 4);
    }
    
    for (size_t i = 0; i < 4; ++i) {
        for (size_t k = 0; k < 4; ++k) {
            for (size_t j = 0; j < 4; ++j) {
                if (CMDS[i][k] == 1)
                    temp_state[i][j] ^= state[k][j];
                else
                    temp_state[i][j] ^= GF_MUL_TABLE[CMDS[i][k]][state[k][j]];
            }
        }
    }
    
    for (size_t i = 0; i < 4; ++i) {
        memcpy(state[i], temp_state[i], 4);
    }
}

void AES::add_round_key(uchar state[4][nb], uchar *key) {
    for (uint i = 0; i < 4; i++) {
        for (uint j = 0; j < nb; j++) {
            state[i][j] = state[i][j] ^ key[i + 4 * j];
        }
    }
}

void AES::sub_word(uchar *a) {
    for (int i = 0; i < 4; i++) {
        a[i] = sbox[a[i] / 16][a[i] % 16];
    }
}

void AES::rot_word(uchar *a) {
    uchar c = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = c;
}

void AES::xor_words(uchar *a, uchar *b, uchar *c) {
    for (int i = 0; i < 4; i++) {
        c[i] = a[i] ^ b[i];
    }
}

void AES::rcon(uchar *a, uint n) {
    uchar c = 1;
    
    for (uint i = 0; i < n - 1; i++) {
        c = xtime(c);
    }
    
    a[0] = c;
    a[1] = a[2] = a[3] = 0;
}

void AES::key_expansion(const uchar* key, uchar* w) {
    uchar temp [4];
    uchar rcon_[4];
    
    uint i = 0;
    while(i < 4 * nk) {
        w[i] = key[i];
        i++;
    }
    
    i = 4 * nk;
    
    while(i < 4 * nb * (nr + 1)) {
        temp[0] = w[i - 4 + 0];
        temp[1] = w[i - 4 + 1];
        temp[2] = w[i - 4 + 2];
        temp[3] = w[i - 4 + 3];
        
        if(i / 4 % nk == 0) {
            rot_word(temp);
            sub_word(temp);
            rcon(rcon_, i / (nk * 4));
            xor_words(temp, rcon_, temp);
        } else if (nk > 6 && i / 4 % nk == 4) {
            sub_word(temp);
        }
        
        w[i + 0] = w[i - 4     * nk] ^ temp[0];
        w[i + 1] = w[i + 1 - 4 * nk] ^ temp[1];
        w[i + 2] = w[i + 2 - 4 * nk] ^ temp[2];
        w[i + 3] = w[i + 3 - 4 * nk] ^ temp[3];
        
        i += 4;
    }
}

void AES::inv_sub_bytes(uchar state[4][nb]) {
    uchar t;
    uint i, j;
    
    for (i = 0; i < 4; i++) {
        for (j = 0; j < nb; j++) {
            t = state[i][j];
            state[i][j] = inv_sbox[t / 16][t % 16];
        }
    }
}

void AES::inv_mix_columns(uchar state[4][nb]) {
    uchar temp_state[4][nb];
    
    for (size_t i = 0; i < 4; ++i) {
        memset(temp_state[i], 0, 4);
    }
    
    for (size_t i = 0; i < 4; ++i) {
        for (size_t k = 0; k < 4; ++k) {
            for (size_t j = 0; j < 4; ++j) {
                temp_state[i][j] ^= GF_MUL_TABLE[INV_CMDS[i][k]][state[k][j]];
            }
        }
    }
    
    for (size_t i = 0; i < 4; ++i) {
        memcpy(state[i], temp_state[i], 4);
    }
}

void AES::inv_shift_rows(uchar state[4][nb]) {
    shift_row(state, 1, nb - 1);
    shift_row(state, 2, nb - 2);
    shift_row(state, 3, nb - 3);
}

void AES::xor_blocks(const uchar* a, const uchar* b, uchar* c, uint length) {
    for (uint i = 0; i < length; i++) {
        c[i] = a[i] ^ b[i];
    }
}
