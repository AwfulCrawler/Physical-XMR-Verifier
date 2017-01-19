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
#include "wallet/password_container.h"

#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>

#include "crypto/hash.h"
#include "cryptonote_core/cryptonote_basic_impl.h"
#include "cryptonote_core/cryptonote_format_utils.h"

#include "message_writer.h"
#include "extended_wallet.h"
#include "sha256.h"
#include "testnet.h"


//--------------------------------------------------------------------------------
bool load_wallet(tools::wallet2& wallet, const std::string& wallet_name)
{
  bool valid_path = tools::wallet2::wallet_valid_path_format(wallet_name);
  if (!valid_path)
  {
    fail_msg_writer() << "wallet file path not valid: " << wallet_name;
    return false;
  }

  bool keys_file_exists;
  bool wallet_file_exists;
  tools::wallet2::wallet_exists(wallet_name, keys_file_exists, wallet_file_exists);
  if (!keys_file_exists || !wallet_file_exists)
  {
    fail_msg_writer() << "keys and/or wallet file are missing";
    return false;
  }

  std::cout << "LOADING WALLET..." << std::endl;
  tools::password_container pwd_container(false); //m_wallet_file will be empty at this point for new wallets
  if (!pwd_container.read_password())
  {
    fail_msg_writer() << "failed to read wallet password";
    return false;
  }

  try
  {
    wallet.load(wallet_name, pwd_container.password());
    message_writer(epee::log_space::console_color_white, true) <<
      (wallet.watch_only() ? "Opened watch-only wallet" : "Opened wallet") << ": "
      << wallet.get_account().get_public_address_str(wallet.testnet());
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << "failed to load wallet: " << e.what();
    return false;
  }
  //wallet.init(m_daemon_address); //probably not necessary
  return true;
}
//--------------------------------------------------------------------------------
void make_digital_certificate(const std::vector<std::string>& args)
{
  tools::extended_wallet m_wallet(TESTNET);

  if (args.empty())
  {
    fail_msg_writer() << "expected wallet name";
    return;
  }
  std::string wallet_name = args[0];

  if (!load_wallet(m_wallet, wallet_name)) return;

  //std::vector<std::tuple<crypto::hash, crypto::public_key, crypto::key_image, uint64_t, crypto::signature>> ski = m_wallet.export_key_images_extended();
  std::vector<tools::signed_output_details> ski = m_wallet.export_key_images_extended();
  std::stringstream message {};
  message << "XMR PHYSICAL COIN CERTIFICATE" << std::endl << std::endl;
  message << "XMR ADDRESS: " <<  m_wallet.get_account().get_public_address_str(m_wallet.testnet()) << std::endl << std::endl;
  message << "VIEW KEY: " << epee::string_tools::pod_to_hex(m_wallet.get_account().get_keys().m_view_secret_key) << std::endl;

  message << "Total # of outputs:" << ski.size() << std::endl;
  message << "*************************************INDIVIDUAL OUTPUT INFORMATION******************************************" << std::endl;
  for (const auto& x : ski)
  {
    message << "key_image: ........" << epee::string_tools::pod_to_hex(x.key_image)  << std::endl;
    message << "tx_id: ............" << epee::string_tools::pod_to_hex(x.txid)       << std::endl;
    message << "output_public_key: " << epee::string_tools::pod_to_hex(x.public_key) << std::endl;
    message << "xmr_amount: ......." << cryptonote::print_money(x.amount) << std::endl << std::endl;
  }
  //message << "-------------------------------------------END-------------------------------------------" << std::endl;

  std::string message_str = message.str();
  crypto::hash hash;
  //crypto::cn_fast_hash(message_str.data(), message_str.size(), hash);
  sha256(message_str, &reinterpret_cast<unsigned char &>(hash));
  //Seems to match sha256sum (in terminal) when sha256sum is run on message_str minus the final std::endl :/
  //
  //gedit appears not to show the final end line if no character follows it, and appears to insert a final endline
  //before the end of the file when saving a text-file.
  //
  //verifying the hash manually with other editors might require playing around with including / excluding an empty line
  //in order to get the correct hash.

  std::stringstream certificate;
  certificate << "HASH:<" << epee::string_tools::pod_to_hex(hash) << ">" << std::endl << std::endl;
  certificate << "--------------------------------------------------START-----------------------------------------------------" << std::endl;
  certificate << message_str;
  certificate << "---------------------------------------------------END------------------------------------------------------" << std::endl << std::endl;

  ski = m_wallet.export_key_images_extended(hash);
  certificate << "SIGNATURES:" << std::endl;
  for (const auto& x : ski)
  {
    crypto::signature s = x.signature; //std::get<4>(x);
    std::string buff;
    buff.assign(reinterpret_cast<const char*>(&s), sizeof(s));
    certificate << "<" << epee::string_tools::buff_to_hex_nodelimer(buff) << ">" << std::endl;
  }

  if (args.size() > 1)
  {
    std::ofstream f(args[1]);
    if (f.is_open())
    {
      f << certificate.str();
      success_msg_writer(true) << "Certificate written to " << args[1];
      f.close();
      return;
    }
    else
    {
      fail_msg_writer() << "Could not open file " << args[1];
      std::cout << "Printing certificate to standard output:";
    }
  }
  std::cout << "----------------------------------------" << std::endl;
  std::cout << certificate.str();
}
//----------------------------------------------------------------------------------------------------------------------
void print_usage(const std::string& my_name)
{
  std::cout << "USAGE: " << my_name <<"  <wallet filename>   [<output filename>]" << std::endl;
}
//----------------------------------------------------------------------------------------------------------------------
int main(int argc, char* argv[])
{
  std::stringstream ss;
  ss << "---------------------------------------------\n"
     << "------EXAMPLE PHYSICAL COIN CERTIFICATE------\n"
     << "---------------------------------------------";

  message_writer(epee::log_space::console_color_white, true)<< ss.str();

#if TESTNET == true
    std::cout << "NOTE: running in testnet mode" << std::endl;
#endif

  if (argc < 2)
  {
    print_usage(std::string(argv[0]));
    return 1;
  }
  std::vector<std::string> arg_vector(argv+1, argv+argc);
  make_digital_certificate(arg_vector);
  std::cout << "------------------------------------------------------------------------------------------------------------" << std::endl;
  return 0;
}
