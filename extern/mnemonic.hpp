/**
 * Copyright (c) 2011-2019 libbitcoin developers (see AUTHORS)
 *
 * This file is part of libbitcoin.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef LIBBITCOIN_SYSTEM_WALLET_MNEMONIC_HPP
#define LIBBITCOIN_SYSTEM_WALLET_MNEMONIC_HPP



// assert.hpp
#define BITCOIN_ASSERT(expression)



// constants.hpp
BC_CONSTEXPR int32_t max_int32 = MAX_INT32;
static uint8_t byte_bits = 8;



// string.hpp
typedef std::vector<std::string> string_list;



// define.hpp
#define BC_API


// data.hpp
template <size_t Size>
using byte_array = std::array<uint8_t, Size>;
typedef std::vector<uint8_t> data_chunk;
typedef array_slice<uint8_t> data_slice;
typedef std::initializer_list<data_slice> loaf;
inline data_chunk build_chunk(loaf slices, size_t extra_reserve=0);
inline data_chunk to_chunk(uint8_t byte);



// hash.hpp
static BC_CONSTEXPR size_t hash_size = 32;
static BC_CONSTEXPR size_t long_hash_size = 2 * hash_size;
typedef byte_array<long_hash_size> long_hash;
typedef byte_array<hash_size> hash_digest;
//~ hash_digest sha256_hash(const data_slice& data);



// electrum.hpp
typedef string_list word_list;




// dictionary.hpp
/**
 * A valid mnemonic dictionary has exactly this many words.
 */
static BC_CONSTEXPR size_t dictionary_size = 2048;
/**
 * Dictionary definitions for creating mnemonics.
 * The bip39 spec calls this a "wordlist".
 * This is a POD type, which means the compiler can write it directly
 * to static memory with no run-time overhead.
 */
typedef std::array<const char*, dictionary_size> dictionary;
typedef std::vector<const dictionary*> dictionary_list;
namespace language {

    // Individual built-in languages:
    extern const dictionary en;

    // Word lists from:
    // github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md
    const dictionary_list all
    {
        &en
    };

} // namespace language




namespace libbitcoin {
namespace system {
namespace wallet {

/**
 * A valid mnemonic word count is evenly divisible by this number.
 */
static BC_CONSTEXPR size_t mnemonic_word_multiple = 3;

/**
 * A valid seed byte count is evenly divisible by this number.
 */
static BC_CONSTEXPR size_t mnemonic_seed_multiple = 4;

/**
 * Represents a mnemonic word list.
 */
typedef string_list word_list;

/**
 * Create a new mnenomic (list of words) from provided entropy and a dictionary
 * selection. The mnemonic can later be converted to a seed for use in wallet
 * creation. Entropy byte count must be evenly divisible by 4.
 */
BC_API word_list create_mnemonic(const data_slice& entropy,
    const dictionary &lexicon=language::en);


/**
 * Checks that a mnemonic is valid in at least one of the provided languages.
 */
BC_API bool validate_mnemonic(const word_list& mnemonic,
    const dictionary_list& lexicons=language::all);

/**
 * Checks a mnemonic against a dictionary to determine if the
 * words are spelled correctly and the checksum matches.
 * The words must have been created using mnemonic encoding.
 */
BC_API bool validate_mnemonic(const word_list& mnemonic,
    const dictionary &lexicon);

/**
 * Convert a mnemonic with no passphrase to a wallet-generation seed.
 */
BC_API long_hash decode_mnemonic(const word_list& mnemonic);

#ifdef WITH_ICU

/**
 * Convert a mnemonic and passphrase to a wallet-generation seed.
 * Any passphrase can be used and will change the resulting seed.
 */
BC_API long_hash decode_mnemonic(const word_list& mnemonic,
    const std::string& passphrase);

#endif

} // namespace wallet
} // namespace system
} // namespace libbitcoin

#endif
