#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include <iostream>

#include "Minet.h"


using std::cout;
using std::endl;
using std::cerr;
using std::string;

int main(int argc, char *argv[])
{
  MinetHandle mux, sock;

  MinetInit(MINET_TCP_MODULE);

  mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
  sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

  if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
    return -1;
  }

  if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
    return -1;
  }

  MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

  MinetEvent event;

  while (MinetGetNextEvent(event)==0) {
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow 
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } else {
      cerr << "\nValid event from Minet, handling...\n" << endl;
	/***************/	
	/***** MUX *****/
	/***************/
      if (event.handle==mux) {
	cerr << "IN MUX HANDLER\n\n";
        Packet p;
	Connection c;
	unsigned char tcp_flags, ip_flags, iph_len, tcph_len;
	unsigned char &iph_len_ptr = iph_len;
	unsigned char &tcph_len_ptr = tcph_len;
	short unsigned int total_len, win_size;
	unsigned int seq_num, ack_num;
        MinetReceive(mux,p);
        unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
        cerr << "estimated header len="<<tcphlen<<"\n";
        p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
        IPHeader ipl=p.FindHeader(Headers::IPHeader);
        TCPHeader tcph=p.FindHeader(Headers::TCPHeader);

        cerr << "TCP Packet: IP Header is "<<ipl<<" and ";
        cerr << "TCP Header is "<<tcph << " and ";

        cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID") << endl;

	/***** Extract Data from packet *****/
	cerr << "\nGETTING CONNECTION INFO FROM PACKET...\n";
	ipl.GetDestIP(c.src);		// get destination IP and store as source
	cerr << "\tSOURCE IP: " << c.src << endl; 
	ipl.GetSourceIP(c.dest);	// get source IP and store as dest
	cerr << "\tDESTINATION IP: " << c.dest << endl;
	tcph.GetDestPort(c.srcport);	// get destination port and store as source
	cerr << "\tSOURCE PORT: " << c.srcport << endl;
	tcph.GetSourcePort(c.destport);	// get source port and store as dest
	cerr << "\tDESTINATION PORT: " << c.destport << endl;
	c.protocol = IP_PROTO_TCP;	// set TCP/IP protocol
	ipl.GetFlags(ip_flags);		// get IP flags
	cerr << "\tIP FLAGS: " << ip_flags << endl;
	tcph.GetFlags(tcp_flags);	// get TCP flags
	cerr << "\tTCP FLAGS: " << tcp_flags << endl;	
	tcph.GetSeqNum(seq_num);	// get Sequence number
	cerr << "\tSEQ NUM: " << seq_num << endl;
	tcph.GetAckNum(ack_num);	// get ACK number
	cerr << "\tACK NUM: " << ack_num << endl;
	tcph.GetWinSize(win_size);	// update window size
	cerr << "\tWINDOW SIZE: " << win_size << endl;
	tcph.GetHeaderLen(tcph_len_ptr); 
	cerr << "\tTCP header length: " << tcph_len << endl;
	ipl.GetTotalLength(total_len);	// total packet size
	cerr << "\tTotal Packet Length: " << total_len << endl;
	ipl.GetHeaderLength(iph_len_ptr);	// IP header length
	cerr << "\tIP header length: " << iph_len << endl;	
	total_len = total_len - tcphlen - iph_len;
	cerr << "\tTOTAL DATA LENGTH: " << total_len << endl;
      }
	/******************/	
	/***** SOCKET *****/
	/******************/
      if (event.handle==sock) {
        SockRequestResponse s;
        MinetReceive(sock,s);
        cerr << "Received Socket Request:" << s << endl;
      }
    }
  }
  return 0;
}
