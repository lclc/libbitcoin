/*
 * Copyright (c) 2011-2013 libbitcoin developers (see AUTHORS)
 *
 * This file is part of libbitcoin.
 *
 * libbitcoin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License with
 * additional permissions to the one published by the Free Software
 * Foundation, either version 3 of the License, or (at your option)
 * any later version. For more information see LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef LIBBITCOIN_EC_KEYS_HPP
#define LIBBITCOIN_EC_KEYS_HPP

#include <bitcoin/define.hpp>
#include <bitcoin/types.hpp>

namespace libbitcoin {

constexpr size_t ec_secret_size = 32;
constexpr size_t ec_compressed_size = 33;
constexpr size_t ec_uncompressed_size = 65;

typedef byte_array<ec_secret_size> ec_secret;
typedef ec_secret secret_parameter; // TODO: Use the new name everywhere

// Import and export:
BC_API data_chunk secret_to_public_key(const ec_secret& secret,
    bool compressed=true);
BC_API bool verify_public_key(const data_chunk& public_key);
BC_API bool verify_private_key(const ec_secret& private_key);

// Signatures:
/* !!! TODO: THESE NEED A SECURE RANDOM NONCE GENERATION SOLUTION !!! */
BC_API data_chunk sign(ec_secret secret, hash_digest hash /*, random_gen */);
BC_API bool verify_signature(const data_chunk& public_key, hash_digest hash,
    const data_chunk& signature);

// Math:
BC_API bool operator+=(data_chunk& a, const ec_secret& b);
BC_API bool operator*=(data_chunk& a, const ec_secret& b);
BC_API bool operator+=(ec_secret& a, const ec_secret& b);
BC_API bool operator*=(ec_secret& a, const ec_secret& b);

} // namespace libbitcoin

#endif

