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

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <stdexcept>
#include <utility>

#include <boost/regex.hpp>
#include <boost/format.hpp>

//From contrib / epee
//-----------------------------
#include "string_tools.h"
#include "misc_log_ex.h"
#include "net/http_client.h"
#include "storages/http_abstract_invoke.h"
//-----------------------------

#include "crypto/hash.h"
#include "cryptonote_core/cryptonote_basic_impl.h"
#include "cryptonote_core/cryptonote_format_utils.h"
#include "cryptonote_core/account.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "ringct/rctSigs.h"
#include "cryptonote_config.h"

#include "testnet.h"
#include "sha256.h"
#include "message_writer.h"

#define RPC_CONNECTION_TIMEOUT 200000
const std::string m_daemon_address {TESTNET ? "http://localhost:28081" : "http://localhost:18081"};  //Should maybe make this a command-line option

struct digital_certificate
{
  cryptonote::account_public_address   m_account_address;
  crypto::secret_key                   m_view_secret_key;

  struct output_details
  {
    crypto::hash        txid;
    crypto::public_key  public_key;
    crypto::key_image   key_image;
    uint64_t            amount;

    output_details(crypto::hash       a_txid       = crypto::hash(),
                   crypto::public_key a_public_key = crypto::public_key(),
                   crypto::key_image  a_key_image  = crypto::key_image(),
                   uint64_t           an_amount    = 0)
      : txid       (a_txid)
      , public_key (a_public_key)
      , key_image  (a_key_image)
      , amount     (an_amount)
      {}
  };

  std::vector<output_details> m_outputs;

};



std::string check_tag_and_get_hex(std::string& line, const std::string& tag);
std::string search_tag_and_get_hex(std::ifstream& f, const std::string& tag);
void dc_get_next_line(std::ifstream& f, std::string& line);
void dc_check_hash(std::ifstream& f, const crypto::hash& hash);
bool load_dc_check_sigs(digital_certificate& dc, const std::string& dc_filename);

static uint64_t decodeRct(const rct::rctSig & rv, const crypto::public_key pub, const crypto::secret_key &sec, unsigned int i, rct::key & mask); //From monero
bool get_tx_pub_key_field(const cryptonote::transaction& tx, cryptonote::tx_extra_pub_key& pub_key_field); //From monero

bool check_connection(); //From monero
std::vector<bool> are_key_images_spent(const std::vector<std::string>& key_images); //From monero
void req_outputs_from_daemon(const digital_certificate& dc, std::vector<std::pair<cryptonote::transaction, crypto::hash>>& transactions);
bool find_output_in_txs(const digital_certificate::output_details& od,
                        const std::vector<std::pair<cryptonote::transaction, crypto::hash>>& transactions,
                        cryptonote::transaction& found_tx, crypto::public_key& found_tx_pub_key, cryptonote::tx_out& found_output, size_t& found_index);

void verify_dc_check_outputs(const std::string& certificate_filename);

void print_output_details(const digital_certificate::output_details& od);
void print_usage(const std::string& my_name);
