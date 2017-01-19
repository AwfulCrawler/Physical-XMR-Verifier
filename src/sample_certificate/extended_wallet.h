//Author: AwfulCrawler
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

#include "wallet/wallet2.h"

namespace tools
{
  struct signed_output_details
  {
    crypto::hash        txid;
    crypto::public_key  public_key;
    crypto::key_image   key_image;
    uint64_t            amount;
    crypto::signature   signature;

    signed_output_details(crypto::hash       a_txid       = crypto::hash(),
                          crypto::public_key a_public_key = crypto::public_key(),
                          crypto::key_image  a_key_image  = crypto::key_image(),
                          uint64_t           an_amount    = 0,
                          crypto::signature  a_signature  = crypto::signature())
                    : txid       (a_txid)
                    , public_key (a_public_key)
                    , key_image  (a_key_image)
                    , amount     (an_amount)
                    , signature  (a_signature)
                    {}
  };

  class extended_wallet: public tools::wallet2
  {
  public:
    extended_wallet(bool testnet = false, bool restricted = false) : wallet2(testnet, restricted) {}
    //std::vector<std::tuple<crypto::hash, crypto::public_key, crypto::key_image, uint64_t, crypto::signature>> export_key_images_extended(crypto::hash hash_input = crypto::hash()) const;
    std::vector<signed_output_details> export_key_images_extended(crypto::hash hash_input = crypto::hash()) const;
  };
}
