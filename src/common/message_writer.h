// Copyright (c) 2014-2016, The Monero Project
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
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers
//

// Modified slightly from message_writer class used in simplewallet (LOG_PRINT / log_level has been removed)

class message_writer
{
public:
  message_writer(epee::log_space::console_colors color = epee::log_space::console_color_default, bool bright = false,
    std::string&& prefix = std::string())
    : m_flush(true)
    , m_color(color)
    , m_bright(bright)
  {
    m_oss << prefix;
  }

  message_writer(message_writer&& rhs)
    : m_flush(std::move(rhs.m_flush))
#if defined(_MSC_VER)
    , m_oss(std::move(rhs.m_oss))
#else
    // GCC bug: http://gcc.gnu.org/bugzilla/show_bug.cgi?id=54316
    , m_oss(rhs.m_oss.str(), ios_base::out | ios_base::ate)
#endif
    , m_color(std::move(rhs.m_color))
  {
    rhs.m_flush = false;
  }

  template<typename T>
  std::ostream& operator<<(const T& val)
  {
    m_oss << val;
    return m_oss;
  }

  ~message_writer()
  {
    if (m_flush)
    {
      m_flush = false;

      //LOG_PRINT(m_oss.str(), m_log_level);

      if (epee::log_space::console_color_default == m_color)
      {
        std::cout << m_oss.str();
      }
      else
      {
        epee::log_space::set_console_color(m_color, m_bright);
        std::cout << m_oss.str();
        epee::log_space::reset_console_color();
      }
      std::cout << std::endl;
    }
  }

private:
  message_writer(message_writer& rhs);
  message_writer& operator=(message_writer& rhs);
  message_writer& operator=(message_writer&& rhs);

private:
  bool m_flush;
  std::stringstream m_oss;
  epee::log_space::console_colors m_color;
  bool m_bright;
  //int m_log_level;
};
//-------------------------------------------------------------------------------
message_writer success_msg_writer(bool color = false)
{
  return message_writer(color ? epee::log_space::console_color_green : epee::log_space::console_color_default, false, std::string());
}
//-------------------------------------------------------------------------------
message_writer fail_msg_writer()
{
  return message_writer(epee::log_space::console_color_red, true, "Error: ");
}
