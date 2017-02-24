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
#include "tcpstate.h"
#include "ip.h"


using std::cout;
using std::endl;
using std::cerr;
using std::string;

#define SYN 	0
#define ACK  	1
#define SYN_ACK 2
#define PSH_ACK 3
#define FIN	4
#define FIN_ACK	5
#define RST	6

void makePacket(Packet &p, ConnectionToStateMapping<TCPState> &ctsm, int type, int data_len);


int main(int argc, char *argv[])
{
  MinetHandle mux, sock;
	ConnectionList<TCPState> conn_list;
	int timeout = 1;
	const char* stateNames[] = {"CLOSED",
	      			"LISTEN",
	      			"SYN_RCVD",
	      			"SYN_SENT",
	      			"SYN_SENT1",
	      			"ESTABLISHED",
	      			"SEND_DATA",
	      			"CLOSE_WAIT",
	      			"FIN_WAIT1",
	      			"CLOSING",
	      			"LAST_ACK",
	      			"FIN_WAIT2",
	      			"TIME_WAIT"};

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

  while (MinetGetNextEvent(event, timeout)==0) {
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
	Packet p_send;	// packet for sending
	Connection c;
	Buffer data_buf;
	SockRequestResponse request;
	SockRequestResponse response;
	unsigned char tcp_flags, ip_flags, iph_len, tcph_len;
	short unsigned int total_len, win_size;
	unsigned int seq_num, ack_num, state;
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
	ipl.GetTotalLength(total_len);	// total packet size
	cerr << "\tTotal Packet Length: " << total_len << endl;
	tcph.GetHeaderLen(tcph_len); 
	cerr << "\tTCP header length: " << tcph_len << endl;
	ipl.GetHeaderLength(iph_len);	// IP header length
	cerr << "\tIP header length: " << iph_len << endl;	
	total_len = total_len - (4 * (tcph_len + iph_len));
	cerr << "\tTOTAL DATA LENGTH: " << total_len << endl;
	data_buf = p.GetPayload().ExtractFront(total_len);
	cerr << "\tDATA: " << data_buf << endl;

	ConnectionList<TCPState>::iterator conn_list_iter = conn_list.FindMatching(c);
	if (conn_list_iter == conn_list.end()) {
		cerr << "\nCONNECTION WAS NOT IN LIST" << endl;
		cerr << "\tAdding connection to list..." << endl;

		TCPState server(1, LISTEN, 5);		// create state server
		ConnectionToStateMapping<TCPState> new_CTSM(request.connection, Time(), server, false);	// mapping
		conn_list.push_back(new_CTSM);		// add new entry to mapping
		response.type = STATUS;
		response.connection = request.connection;
		response.bytes = 0;
		response.error = EOK;
		cerr << "\tSending Response..." << endl;
		//MinetSend(sock, response);
		cerr << "\tResponse Sent via MinetSend" << endl;
	}
	state = conn_list_iter->state.GetState();	// get the current state of the connection
	cerr << "\nCURRENT CONNECTION STATE: " << stateNames[state] << endl;

	switch(state) {
		case LISTEN:
			cerr << "LISTENING in MUX..." << endl;			
			if (IS_SYN(tcp_flags)) {				// SYN Packet received
				cerr << "\tSYN packet received" << endl;
				conn_list_iter->connection = c;
				conn_list_iter->state.SetState(SYN_RCVD);	// Set state to SYN_RCVD
				conn_list_iter->state.last_acked = conn_list_iter->state.last_sent;
				conn_list_iter->state.SetLastRecvd(seq_num + 1);
				conn_list_iter->bTmrActive = true;	// set timeout
				conn_list_iter->timeout = Time() + 5;	// 5 seconds
				
				conn_list_iter->state.last_sent = conn_list_iter->state.last_sent + 1;
				makePacket(p_send, *conn_list_iter, SYN_ACK, 0); // build a SYNACK packet
				cerr << "\tAttempting to send SYNACK packet" << endl;
				MinetSend(mux, p_send);	// send SYNACK packet
				//sleep(2);			// wait 2 seconds
				//MinetSend(mux, p_send);	// resend SYNACK packet
			}
			cerr << "FINISHED LISTENING" << endl;
			break;
	      	case SYN_RCVD:
			cerr << "SYN Received" << endl;
			cerr << "CONNECTION ESTABLISHED!" << endl;
			conn_list_iter->state.SetState(ESTABLISHED);
			conn_list_iter->state.SetLastAcked(ack_num);	
			/***** increment sequence number *****/
			conn_list_iter->state.last_sent = conn_list_iter->state.last_sent + 1;
			conn_list_iter->bTmrActive = false;
			static SockRequestResponse *write = NULL;
			write = new SockRequestResponse(WRITE, conn_list_iter->connection, data_buf, 0, EOK);
			MinetSend(sock,*write);
			delete write;
			cerr << "Response written to socket" << endl;
			cerr << "FINISHED SYN_RCVD" << endl;
			break;
	      	case SYN_SENT:
			cerr << "SYN Sent" << endl;
			break;
	      	case SYN_SENT1:
			cerr << "SYN SENT 1" << endl;
			break;
	      	case ESTABLISHED:
			cerr << "ESTABLISHED" << endl;
			if (IS_FIN(tcp_flags) && IS_ACK(tcp_flags)) {
				cerr << "\treceived FINACK packet" << endl;
			} else if (IS_PSH(tcp_flags) && IS_ACK(tcp_flags)) {
				cerr << "\treceived data packet" << endl;
			} else if (IS_ACK(tcp_flags)) {
				cerr << "\treceived ACK packet" << endl;
			} else {
				cerr << "\tWARNING: received unexpected packet" << endl;
			}
			cerr << "EXITING ESTABLISHED STATE" << endl;
			break;
	      	case SEND_DATA:
			cerr << "SEND DATA" << endl;
			break;
	      	case CLOSE_WAIT:
			cerr << "CLOSE WAIT" << endl;
			break;
	      	case FIN_WAIT1:
			cerr << "FIN WAIT 1" << endl;
			break;
	      	case CLOSING:
			cerr << "CLOSING" << endl;
			break;
	      	case LAST_ACK:
			cerr << "LAST ACK" << endl;
			break;
	      	case FIN_WAIT2:
			cerr << "FIN WAIT 2" << endl;
			break;
		default:
			cerr << "ENTERED DEFAULT CASE" << endl;
			break;
	}

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


void makePacket(Packet &p, ConnectionToStateMapping<TCPState> &ctsm, int type, int data_len) {
	int total_len = data_len + IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH;
	unsigned char flags;
	cerr << "\n***** BUILDING PACKET *****" << endl;
	/***** SET IP HEADER *****/	
	IPHeader iph;
	iph.SetProtocol(IP_PROTO_TCP);		// set to TCP/IP protocol
	iph.SetSourceIP(ctsm.connection.src);	// set source IP address
	iph.SetDestIP(ctsm.connection.dest);	// set destination IP address
	iph.SetTotalLength(total_len);		// set packet size
	p.PushFrontHeader(iph);			// add IP header to packet
	cerr << "\tIP Header created" << endl;
	/***** SET TCP HEADER *****/	
	TCPHeader tcph;
	tcph.SetSourcePort(ctsm.connection.srcport, p);	// add source port
	tcph.SetDestPort(ctsm.connection.destport, p);	// add dest port
	tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, p);	// add header length
	tcph.SetAckNum(ctsm.state.GetLastRecvd(), p);	// set ack number
	tcph.SetWinSize(ctsm.state.GetRwnd(), p);	// set window size
	tcph.SetUrgentPtr(0, p);			// set urgency to 0
	cerr << "\tselecting packet type..." << endl;

	switch (type) {		// set flags based on type
		case SYN:
			SET_SYN(flags);	// set as a SYN
			break;
		case ACK:
			SET_ACK(flags);	// set as an ACK
			break;
		case SYN_ACK:
			SET_SYN(flags);	// set as a SYN
			SET_ACK(flags);	// set as an ACK
			break;
		case PSH_ACK:
			SET_PSH(flags);	// set as a PSH
			SET_ACK(flags);	// set as an ACK
			break;
		case FIN:
			SET_FIN(flags);	// set as a FIN
			break;
		case FIN_ACK:
			SET_FIN(flags);	// set as a FIN
			SET_ACK(flags);	// set as an ACK
			break;
		case RST:
			SET_RST(flags); // set as a RST
			break;
		default:
			cerr << "INVALID PACKET TYPE SPECIFIED" << endl;
			break;
	}
	tcph.SetFlags(flags, p);		// set flags
	tcph.SetSeqNum(ctsm.state.GetLastSent(), p);	// set sequence number
	tcph.RecomputeChecksum(p);		// compute checksum
	p.PushBackHeader(tcph);
	cerr << "\tTCP Header added" << endl;
	cerr << "***** PACKET BUILT SUCCESSFULLY *****" << endl;
}
