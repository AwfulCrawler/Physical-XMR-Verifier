//Author: AwfulCrawler
//
// Parts of this file are orignally copyright (c) 2014-2016, The Monero Project
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

#include "certificate_verifier.h"

//----------------------------------------------------------------------------------------------------------------------
//GLOBAL
epee::net_utils::http::http_simple_client m_http_client;
boost::regex hex_regex(R"([a-f0-9]+$)");
boost::regex number_regex(R"([0-9]+)");
boost::regex decimal_regex(R"([0-9]+\.[0-9]+)");        //Had trouble when a single regex for numbers.  Split into 'number' and 'decimal' for now.
boost::regex address_regex(R"((4|9|A)[0-9a-zA-Z]+$)");  //Include testnet addresses (which start with '9' or 'A')

//----------------------------------------------------------------------------------------------------------------------
std::string check_tag_and_get_hex(std::string& line, const std::string& tag)
{
  boost::smatch match;
  if (line.find(tag) == std::string::npos){ throw std::runtime_error("missing tag: " + tag); }
  if (line.back() == '>') line.pop_back();
  boost::regex_search(line, match, hex_regex);
  return match.str();
}
//----------------------------------------------------------------------------------------------------------------------
//Originally was passing a reference to a boost::smatch rather than returning std::string.
//But that seemed to produce some errors when detecting hits, which were fixed by
//keeping boost::smatch within the scope of the line variable. As if smatch doesn't store matchign substrings
//but just references ranges in the search string.
//
//Boost documentation seems to confirm this as far as I can see: matches contain sub-matches which are
//defined by a pair of iterators... i,e, sub-matches are not strings themselves but rather defined by
//pointers to the start and end of where the 'sub-match' is.
std::string search_tag_and_get_hex(std::ifstream& f, const std::string& tag)
{
  boost::smatch match;
  std::string line;
  do { if(!getline(f, line)) { throw std::runtime_error("missing tag: " + tag); } } while (line.find(tag) == std::string::npos);
  return check_tag_and_get_hex(line, tag);
}
//----------------------------------------------------------------------------------------------------------------------
void dc_get_next_line(std::ifstream& f, std::string& line)
{
  if(!getline(f, line)) { throw std::runtime_error("premature end of file"); }
}
//----------------------------------------------------------------------------------------------------------------------
void dc_check_hash(std::ifstream& f, const crypto::hash& hash)
{
  std::string       line;
  std::stringstream message;
  crypto::hash      message_hash;

  do { if(!getline(f, line)) { throw std::runtime_error("missing START of message in digital certificate"); } } while (line.find("-START-") == std::string::npos);
  message << line << "\n";

  do
  {
    if (!getline(f,line))
      throw std::runtime_error("file ended before message end");

    message << line << "\n";
  }
  while(line.find("-END-") == std::string::npos);

  //Reset the fstream back to the beginning of the file.
  f.seekg(0);

  //std::cout << "-------------------------START---------------------------" << std::endl;
  //std::cout << message.str();
  //std::cout << "--------------------------END----------------------------" << std::endl;

  //Need to replace with the hash that smoothie uses.
  //
  crypto::cn_fast_hash(message.str().data(), message.str().size(), message_hash);
  //sha256(message.str(), &reinterpret_cast<unsigned char &>(message_hash)); //Has been tested against command-line sha256sum
  if (message_hash != hash)
  {
    message_writer(epee::log_space::console_color_yellow, true) << "WARNING: hash of message does not match hash on certificate:\n"
      << "        Calculated hash: <" << epee::string_tools::pod_to_hex(message_hash) << ">\n" //<< std::endl;
      << "    Hash on certificate: <" << epee::string_tools::pod_to_hex(hash) << ">"; //<< std::endl;
  }
}
//----------------------------------------------------------------------------------------------------------------------
bool load_dc_check_sigs(digital_certificate& dc, const std::string& dc_filename)
{
  std::string line;
  std::string str_match;
  boost::smatch smatch;

  std::ifstream f(dc_filename);
  if (!f.is_open())
  {
    fail_msg_writer() << "could not open file " << dc_filename;
    return false;
  }
  //----------FIND THE HASH---------//
  crypto::hash hash;
  str_match = search_tag_and_get_hex(f, "HASH");
  epee::string_tools::hex_to_pod(str_match, hash);
  //--------------------------------//

  dc_check_hash(f, hash);

  //--------GET THE ADDRESS--------//
  bool has_payment_id;
  crypto::hash8 new_payment_id;

  do { dc_get_next_line(f, line); } while(line.find("ADDRESS") == std::string::npos);
  boost::regex_search(line, smatch, address_regex);

  //std::cout << "ADDR = " << smatch.str() << std::endl;

  if(!get_account_integrated_address_from_str(dc.m_account_address, has_payment_id, new_payment_id, TESTNET, smatch.str()))
  {
      fail_msg_writer() << "failed to parse address";
      return false;
  }
  //-------------------------------//

  //--------GET THE VIEWKEY--------//
  do { dc_get_next_line(f, line); } while(line.find("VIEW") == std::string::npos);
  boost::regex_search(line, smatch, hex_regex);
  epee::string_tools::hex_to_pod(smatch.str(), dc.m_view_secret_key);
  //-------------------------------//

  // check that the viewkey matches the given address
  crypto::public_key pkey;
  if (!crypto::secret_key_to_public_key(dc.m_view_secret_key, pkey)) {
    message_writer(epee::log_space::console_color_red, true) << "Failed to verify secret viewkey";
    return false;
  }
  if (dc.m_account_address.m_view_public_key != pkey) {
    message_writer(epee::log_space::console_color_red, true) << "Viewkey does not match standard address";
    return false;
  }

  //Get total number of outputs:
  do { dc_get_next_line(f, line); } while(line.find("Total") == std::string::npos);
  boost::regex_search(line, smatch, number_regex);
  int num_outputs = std::stoi(smatch.str(),nullptr);
  dc.m_outputs.reserve(num_outputs);


  for (int i=0;i<num_outputs;i++)
  {
    crypto::key_image ki;
    crypto::hash      txid;
    crypto::public_key pkey;
    uint64_t          amount;

    str_match = search_tag_and_get_hex(f, "key_image");
    //std::cout << match.str() << std::endl;
    epee::string_tools::hex_to_pod(str_match, ki);


    dc_get_next_line(f, line);
    str_match = check_tag_and_get_hex(line, "tx_id");
    epee::string_tools::hex_to_pod(str_match, txid);

    dc_get_next_line(f, line);
    str_match = check_tag_and_get_hex(line, "output_public_key");
    epee::string_tools::hex_to_pod(str_match, pkey);

    dc_get_next_line(f, line);
    if (line.find("xmr_amount") == std::string::npos) { throw std::runtime_error("missing tag: xmr_amount"); }
    boost::regex_search(line, smatch, decimal_regex);
    if(!cryptonote::parse_amount(amount, smatch.str())) { throw std::runtime_error("could not parse XMR amount"); }
    dc.m_outputs.push_back(digital_certificate::output_details(txid, pkey, ki, amount));
  }
  dc_get_next_line(f, line);
  dc_get_next_line(f, line);
  if (line.find("END") == std::string::npos) { throw std::runtime_error("Non-standard format between START and END on certificate."); }

  //--------------------------------------------------------------------------------------------------------------------
  //SIGNATURE CHECKING
  //--------------------------------------------------------------------------------------------------------------------
  do { dc_get_next_line(f, line); } while ( line.find("SIGNATURES") == std::string::npos );

  for (int i=0;i<num_outputs;i++)
  {
    dc_get_next_line(f, line);
    if (line.back() == '>') line.pop_back();
    boost::regex_search(line, smatch, hex_regex);
    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(smatch.str(), blob)) {f.close(); return false; }
    const crypto::signature s = *reinterpret_cast<const crypto::signature*>(blob.data());

    crypto::key_image  ki   = dc.m_outputs[i].key_image;
    crypto::public_key pkey = dc.m_outputs[i].public_key;
    std::vector<const crypto::public_key*> pkeys;
    pkeys.push_back(&pkey);

    if(!crypto::check_ring_signature(hash, ki, pkeys, &s))
    {
      message_writer(epee::log_space::console_color_red,true) << "Signature check failed on output index " << i;
      print_output_details(dc.m_outputs[i]);
      f.close();
      return false;
    }
  }

  f.close();
  return true;
}
//----------------------------------------------------------------------------------------------------------------------
//Taken from monero wallet2::decodeRct verbatim except for LOG_ERROR replaced with fail_msg_writer()
static uint64_t decodeRct(const rct::rctSig & rv, const crypto::public_key pub, const crypto::secret_key &sec, unsigned int i, rct::key & mask)
{
  crypto::key_derivation derivation;
  bool r = crypto::generate_key_derivation(pub, sec, derivation);
  if (!r)
  {
    fail_msg_writer() << "Failed to generate key derivation to decode rct output " << i;
    return 0;
  }
  crypto::secret_key scalar1;
  crypto::derivation_to_scalar(derivation, i, scalar1);
  try
  {
    switch (rv.type)
    {
    case rct::RCTTypeSimple:
      return rct::decodeRctSimple(rv, rct::sk2rct(scalar1), i, mask);
    case rct::RCTTypeFull:
      return rct::decodeRct(rv, rct::sk2rct(scalar1), i, mask);
    default:
      fail_msg_writer() << "Unsupported rct type: " << rv.type;
      return 0;
    }
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << "Failed to decode input " << i;
    return 0;
  }
}
//----------------------------------------------------------------------------------------------------------------------
//Taken and modified from wallet2::export_key_images
bool get_tx_pub_key_field(const cryptonote::transaction& tx, cryptonote::tx_extra_pub_key& pub_key_field)
{
  std::vector<cryptonote::tx_extra_field> tx_extra_fields;
  if(!cryptonote::parse_tx_extra(tx.extra, tx_extra_fields))
  {
    // Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
  }

  if(!cryptonote::find_tx_extra_field_by_type(tx_extra_fields, pub_key_field))
    return false;
  else
    return true;
}
//----------------------------------------------------------------------------------------------------------------------
//Ripped from wallet2::check_connection
bool check_connection()
{
  if(!m_http_client.is_connected())
  {
    epee::net_utils::http::url_content u;
    epee::net_utils::parse_url(m_daemon_address, u);

    if(!u.port)
    {
      u.port = config::RPC_DEFAULT_PORT;
    }

    if (!m_http_client.connect(u.host, std::to_string(u.port), RPC_CONNECTION_TIMEOUT))
      return false;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------------------------
//Ripped and modified for exception-throwing from wallet2::import_key_images
std::vector<bool> are_key_images_spent(const std::vector<std::string>& key_images)
{
  if (!check_connection)
    throw std::runtime_error("timeout while connecting to daemon");

  cryptonote::COMMAND_RPC_IS_KEY_IMAGE_SPENT::request req = AUTO_VAL_INIT(req);
  cryptonote::COMMAND_RPC_IS_KEY_IMAGE_SPENT::response daemon_resp = AUTO_VAL_INIT(daemon_resp);

  for (const std::string& ki : key_images)
    req.key_images.push_back(ki);

  bool r = epee::net_utils::invoke_http_json_remote_command2(m_daemon_address + "/is_key_image_spent", req, daemon_resp, m_http_client, RPC_CONNECTION_TIMEOUT);
  if(!r)
    throw std::runtime_error("rpc_command fail: is_key_image_spent");
  else if(daemon_resp.status == CORE_RPC_STATUS_BUSY)
    throw std::runtime_error("Daemon busy");
  else if(daemon_resp.status != CORE_RPC_STATUS_OK)
    throw std::runtime_error("Daemon no 'ok'" + daemon_resp.status);
  else if(daemon_resp.spent_status.size() != req.key_images.size())
    throw std::runtime_error("Daemon returned wrong response for is_key_image_spent, wrong amounts count = " +
            std::to_string(daemon_resp.spent_status.size()) + ", expected " +  std::to_string(req.key_images.size()));

  std::vector<bool> spent_status;
  for (size_t n = 0; n < daemon_resp.spent_status.size(); ++n)
    if (daemon_resp.spent_status[n] != cryptonote::COMMAND_RPC_IS_KEY_IMAGE_SPENT::UNSPENT)
      spent_status.push_back(true);
    else
      spent_status.push_back(false);

  return spent_status;
}
//----------------------------------------------------------------------------------------------------------------------
void req_outputs_from_daemon(const digital_certificate& dc, std::vector<std::pair<cryptonote::transaction, crypto::hash>>& transactions)
{
  if (!check_connection)
    throw std::runtime_error("timeout while connecting to daemon");

  cryptonote::COMMAND_RPC_GET_TRANSACTIONS::request  req         = AUTO_VAL_INIT(req);
  cryptonote::COMMAND_RPC_GET_TRANSACTIONS::response daemon_resp = AUTO_VAL_INIT(daemon_resp);

  for (const digital_certificate::output_details& od : dc.m_outputs)
  {
    std::string txid_str = epee::string_tools::pod_to_hex(od.txid);
    if(std::find(req.txs_hashes.begin(), req.txs_hashes.end(), txid_str) == req.txs_hashes.end())
      req.txs_hashes.push_back(txid_str);
  }

  req.decode_as_json = false;
  bool r = epee::net_utils::invoke_http_json_remote_command2(m_daemon_address + "/gettransactions", req, daemon_resp, m_http_client, 200000);
  if(!r)
    throw std::runtime_error("rpc_command fail. /gettransactions failed. Possible bad txid");
  else if(daemon_resp.status == CORE_RPC_STATUS_BUSY)
    throw std::runtime_error("Daemon busy");
  else if(daemon_resp.status != CORE_RPC_STATUS_OK)
    throw std::runtime_error("Daemon not 'ok' ");

  for (const auto& x : daemon_resp.txs)
  {
    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(x.as_hex, blob))
    {
      throw std::runtime_error("Couldn't convert hex transaction to blob");
    }
    cryptonote::transaction tx;
    if (!parse_and_validate_tx_from_blob(blob, tx))
      throw std::runtime_error("Error parsing tx from blobdata");

    cryptonote::tx_extra_pub_key pub_key_field;
    if (!get_tx_pub_key_field(tx, pub_key_field))
      throw std::runtime_error( "Public key wasn't found in the transaction extra");

    crypto::hash txid;
    if (!epee::string_tools::hex_to_pod(x.tx_hash, txid))
      throw std::runtime_error( "error converting tx_hash from daemon response to txid");

    transactions.push_back(std::make_pair(tx, txid));
  }
}
//----------------------------------------------------------------------------------------------------------------------
bool find_output_in_txs(const digital_certificate::output_details& od,
                        const std::vector<std::pair<cryptonote::transaction, crypto::hash>>& transactions,
                        cryptonote::transaction& found_tx, crypto::public_key& found_tx_pub_key, cryptonote::tx_out& found_output, size_t& found_index)
{
  bool found = false;
  for (const auto& x : transactions)
  {
    cryptonote::transaction tx   = x.first;
    crypto::hash            txid = x.second;
    for (size_t i=0; i<tx.vout.size(); i++)
    {
      const cryptonote::tx_out &out = tx.vout[i];
      crypto::public_key td_pkey;
      try
      {
        const cryptonote::txout_to_key &o = boost::get<const cryptonote::txout_to_key>(out.target);
        td_pkey = o.key;
      }
      catch ( const std::exception& e)
      {
        throw e;
      }

      cryptonote::tx_extra_pub_key pub_key_field;
      if (!get_tx_pub_key_field(tx, pub_key_field))
        throw std::runtime_error( "Public key wasn't found in the transaction extra");

      if (txid == od.txid && td_pkey == od.public_key)
      {
        found_tx_pub_key = pub_key_field.pub_key;
        found_tx         = tx;
        found_output     = out;
        found_index      = i;
        found            = true;
        break;
      }
    }
    if (found) break;
  }
  return found;
}
//----------------------------------------------------------------------------------------------------------------------
void verify_dc_check_outputs(const std::string& certificate_filename)
{
  digital_certificate dc;
  try
  {
    //load_dc_check_sigs(dc, certificate_fname);
    if (!load_dc_check_sigs(dc, certificate_filename))
    {
      fail_msg_writer() << "failed to load and verify digital certificate";
      return;
    }
  }
  catch (std::exception &e)
  {
    fail_msg_writer() << "error reading certificate: " << e.what();
    return;
  }
  success_msg_writer(true) << "SIGNATURES VERIFIED";
  std::cout << "Checking that outputs exist and belong to the given address in the certificate..." << std::endl;

  std::vector<std::pair<cryptonote::transaction, crypto::hash>> transactions;
  try
  {
    req_outputs_from_daemon(dc, transactions);
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << "while getting transactions from daemon: " << e.what();
    return;
  }

  cryptonote::transaction found_tx;
  crypto::public_key found_tx_pub_key;
  cryptonote::tx_out found_output;
  size_t found_index;
  for (size_t i=0;i<dc.m_outputs.size(); i++)
  {
    const digital_certificate::output_details& od = dc.m_outputs[i];
    bool found = false;
    try
    {
      found = find_output_in_txs(od, transactions, found_tx, found_tx_pub_key, found_output, found_index);
    }
    catch (const std::exception &e)
    {
      fail_msg_writer() << "while searching txs returned from daemon:" << e.what();
      return;
    }

    if (!found)
    {
      fail_msg_writer() << "Output " << i << " not found";
      print_output_details(od);
      return;
    }

    //Check whether the output belongs to the address / viewkey given on the certificate
    //
    //Wallet2 (v0.10.0) calls is_out_to_acc in the same way in wallet2::check_acc_out, which
    //is called from wallet2::process_new_transaction()
    cryptonote::account_keys acc;
    acc.m_account_address = dc.m_account_address;
    acc.m_view_secret_key = dc.m_view_secret_key;
    bool received = cryptonote::is_out_to_acc(acc, boost::get<cryptonote::txout_to_key>(found_output.target), found_tx_pub_key, found_index);
    if (!received)
    {
      fail_msg_writer() << "Output " << i << " not owned by the address listed on certificate";
      print_output_details(od);
      return;
    }

    //Some sort of check.  I'm not sure exactly what this does.
    //Taken from wallet2::process_new_transaction() in v0.10.0 release
    crypto::key_image ki;
    cryptonote::keypair in_ephemeral;
    rct::key mask;
    cryptonote::generate_key_image_helper(acc, found_tx_pub_key, found_index, in_ephemeral, ki);
    if(in_ephemeral.pub != boost::get<cryptonote::txout_to_key>(found_output.target).key)
    {
      fail_msg_writer() << "key_image generated ephemeral public key not matched with output_key";
      print_output_details(od);
      return;
    }

    //If it's a ringct output then get the amount using the viewkey
    if (found_output.amount == 0)
    {
      uint64_t money_transfered = decodeRct(found_tx.rct_signatures, found_tx_pub_key, acc.m_view_secret_key, found_index, mask);
      found_output.amount       = money_transfered;
    }

    //Check that the output amount actually matches the amount on the certificate
    if (found_output.amount != od.amount)
    {
      fail_msg_writer() << "Amount listed on certificate for output " << i << " does not match the data from the daemon:";
      print_output_details(od);
      message_writer(epee::log_space::console_color_red,true) << "Amount from daemon = " << cryptonote::print_money(found_output.amount);
      return;
    }
  }
  success_msg_writer(true) << "Tx IDs, Outputs and Amounts found on blockchain and belong to the address on the certificate";
  std::cout << "Checking spent status..." << std::endl;
  std::cout << "---------------------------------------------OUTPUTS-------------------------------------------------" << std::endl;

  std::vector<std::string> key_images;
  for (const auto& x : dc.m_outputs)
    key_images.push_back(epee::string_tools::pod_to_hex(x.key_image));

  std::vector<bool> spent_status;
  try
  {
    spent_status = are_key_images_spent(key_images);
  }
  catch (std::exception &e)
  {
    fail_msg_writer() << "error checking spent status of key image: " << e.what();
    return;
  }

  if (dc.m_outputs.size() > 0)
    message_writer() << boost::format("%21s%12s%68s") % "amount" % "status" % "pubkey";
  //Check spent vs unspent key images.
  for (size_t i=0; i<dc.m_outputs.size(); i++)
  {
    const digital_certificate::output_details& x  = dc.m_outputs[i];
    bool  output_spent = spent_status[i];

    std::string pkey   = epee::string_tools::pod_to_hex(x.public_key);
    uint64_t    amount = x.amount;
    message_writer(output_spent ? epee::log_space::console_color_magenta : epee::log_space::console_color_green, false) <<
      boost::format("%21s%12s%68s") %
      cryptonote::print_money(amount) %
      (output_spent ? "SPENT" : "UNSPENT") %
      pkey;
  }
}
//----------------------------------------------------------------------------------------------------------------------
void print_output_details(const digital_certificate::output_details& od)
{
  std::cout << "----------------------OUTPUT DETAILS----------------------" << std::endl;
  std::cout << "key_image: ........" << epee::string_tools::pod_to_hex(od.key_image)  << std::endl;
  std::cout << "tx_id: ............" << epee::string_tools::pod_to_hex(od.txid)       << std::endl;
  std::cout << "output_public_key: " << epee::string_tools::pod_to_hex(od.public_key) << std::endl;
  std::cout << "xmr_amount: ......." << cryptonote::print_money(od.amount)            << std::endl;
}
//----------------------------------------------------------------------------------------------------------------------
void print_usage(const std::string& my_name)
{
  std::cout << "USAGE: " << my_name <<" <certificate filename>" << std::endl;
}
//----------------------------------------------------------------------------------------------------------------------
int main(int argc, char* argv[])
{
  std::stringstream ss;
  ss << "--------------------------------------------\n"
     << "---PHYSICAL COIN CERTIFICATE VERIFICATION---\n"
     << "--------------------------------------------";

  message_writer(epee::log_space::console_color_white, true) << ss.str();

#if TESTNET == true
    std::cout << "NOTE: running in testnet mode" << std::endl;
#endif

  std::vector<std::string> arg_vector(argv+1, argv+argc);
  if (argc < 2)
  {
    print_usage(std::string(argv[0]));
    return 1;
  }
  verify_dc_check_outputs(std::string(argv[1]));
  std::cout << "-----------------------------------------------------------------------------------------------------" << std::endl;
  return 0;
}
