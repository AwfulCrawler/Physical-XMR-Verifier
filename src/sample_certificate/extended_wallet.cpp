//Author: AwfulCrawler
//
// Orignally copyright (c) 2014-2016, The Monero Project
// and copyright (c) 2012-2013 The Cryptonote developers
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

// This code is taken and modified from wallet2::export_key_images

#include "extended_wallet.h"

namespace tools
{
  //std::vector<std::tuple<crypto::hash, crypto::public_key, crypto::key_image, uint64_t, crypto::signature>> extended_wallet::export_key_images_extended(crypto::hash hash_input) const
  std::vector<signed_output_details> extended_wallet::export_key_images_extended(crypto::hash hash_input) const
  {
    //std::vector<std::tuple<crypto::hash, crypto::public_key, crypto::key_image, uint64_t, crypto::signature>> ski;
    std::vector<signed_output_details> ski;

    tools::wallet2::transfer_container transfers;
    this->get_transfers(transfers);

    ski.reserve(transfers.size());

    //for (size_t n = 0; n < m_transfers.size(); ++n)
    for (const auto &td : transfers)
    {
      //const transfer_details &td = m_transfers[n];

      // get ephemeral public key
      const cryptonote::tx_out &out = td.m_tx.vout[td.m_internal_output_index];
      THROW_WALLET_EXCEPTION_IF(out.target.type() != typeid(cryptonote::txout_to_key), error::wallet_internal_error,
          "Output is not txout_to_key");
      const cryptonote::txout_to_key &o = boost::get<const cryptonote::txout_to_key>(out.target);
      const crypto::public_key pkey = o.key;

      // get tx pub key
      std::vector<cryptonote::tx_extra_field> tx_extra_fields;
      if(!cryptonote::parse_tx_extra(td.m_tx.extra, tx_extra_fields))
      {
        // Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
      }
      cryptonote::tx_extra_pub_key pub_key_field;
      THROW_WALLET_EXCEPTION_IF(!find_tx_extra_field_by_type(tx_extra_fields, pub_key_field), error::wallet_internal_error,
          "Public key wasn't found in the transaction extra");
      crypto::public_key tx_pub_key = pub_key_field.pub_key;

      // generate ephemeral secret key
      crypto::key_image ki;
      cryptonote::keypair in_ephemeral;
      cryptonote::generate_key_image_helper(this->get_account().get_keys(), tx_pub_key, td.m_internal_output_index, in_ephemeral, ki);

      THROW_WALLET_EXCEPTION_IF(ki != td.m_key_image,
          error::wallet_internal_error, "key_image generated not matched with cached key image");
      THROW_WALLET_EXCEPTION_IF(in_ephemeral.pub != pkey,
          error::wallet_internal_error, "key_image generated ephemeral public key not matched with output_key");

      // sign the key image with the output secret key
      crypto::signature signature;
      std::vector<const crypto::public_key*> key_ptrs;
      key_ptrs.push_back(&pkey);

      crypto::generate_ring_signature(hash_input, td.m_key_image, key_ptrs, in_ephemeral.sec, 0, &signature);

      ski.push_back(signed_output_details(td.m_txid, pkey ,td.m_key_image, td.amount(), signature));
    }
    return ski;
  }
}
