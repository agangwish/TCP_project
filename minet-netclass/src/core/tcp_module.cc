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

#include <queue>

using namespace std;

Packet buildPacket(Connection c, 
		unsigned int id, 
		unsigned int seqnum, 
		unsigned int acknum, 
		unsigned short winsize, 
		unsigned char hlen, 
		unsigned short urgptr, 
		unsigned char flags, 
		const char *data, 
		size_t datalen);

int main(int argc, char *argv[])
{
	MinetHandle mux, sock;
	ConnectionList<TCPState> conn_list;
	queue<SockRequestResponse> SocksPending;
	queue<SockRequestResponse> empty;
	SockRequestResponse request, response, close;
	int is_p_connected = 0, is_a_connected = 0, is_first = 1;

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

	double min_timeout = -1;
	Buffer tdata;
	Buffer &data = tdata;
	unsigned char oldflags, flags = 0, hlen = 5;
	unsigned int acknum = 0, seqnum = 0, id = rand() % 10000;
	unsigned short winsize = 14600, uptr = 0;


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

	while (MinetGetNextEvent(event, min_timeout)==0) {
		flags = 0;
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
				cerr << "IN MUX HANDLER" << endl;
				Packet p;
				Connection c;
				MinetReceive(mux,p);
				unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);

				p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
				IPHeader ipl=p.FindHeader(Headers::IPHeader);
				TCPHeader tcph=p.FindHeader(Headers::TCPHeader);

				cerr << "TCP Packet: IP Header is "<<ipl<<" and ";
				cerr << "TCP Header is "<<tcph << " and ";

				cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID") << endl;


				tcph.GetFlags(oldflags);
				tcph.GetSeqNum(acknum);
				tcph.GetAckNum(seqnum);
				tcph.GetWinSize(winsize);


				if (seqnum == 0) {
					seqnum = rand() % 50000;
				}

				ipl.GetSourceIP(c.dest);
				ipl.GetDestIP(c.src);
				tcph.GetDestPort(c.srcport);
				tcph.GetSourcePort(c.destport);
				c.protocol = IP_PROTO_TCP;

				ConnectionList<TCPState>::iterator cs = conn_list.FindMatching(c);	
				if (!is_a_connected  && !is_p_connected && (IS_FIN(oldflags) || IS_RST(oldflags))) {
					SET_FIN(flags);
					SET_ACK(flags);
					Packet newp = buildPacket(c, id, seqnum, acknum + 1, winsize, hlen, uptr, flags, "", 0);
					MinetSend(mux, newp);
					cs = conn_list.begin();
					continue;
				}

				if (!is_p_connected && (IS_FIN(oldflags)  || IS_SYN(oldflags) || IS_RST(oldflags)  || IS_ACK(oldflags)))    {
					SET_FIN(flags);
					SET_ACK(flags);
					Packet newp = buildPacket(c, id, seqnum, acknum + 1, winsize, hlen, uptr, flags, "", 0);
					MinetSend(mux, newp);
					cs = conn_list.begin();
					continue;
				}

				if (cs == conn_list.end() || is_p_connected == 0) {
					is_p_connected  = 1;
					cerr << "CONNECTION WAS NOT IN LIST" << endl;
					cerr << "THE PASSIVE OPEN SOCKET IS NOT BOUND" << endl;
					cs = conn_list.begin();

					if(is_first == 2)
					{
						is_first = 3;
						cerr << "CONNECTING TO THE PASSIVE OPEN SOCKET" << endl;

						response.type = STATUS;
						response.connection = c;
						response.bytes = 0;
						response.error = EOK;
						MinetSend(sock, response);
						cerr << "INITIAL SOCK SEND: " << response << endl;
						cerr << "Requesting new socket" << endl;
						cs = conn_list.FindMatching(c);
					}
					else if(is_first == 0)
					{
						is_first = 3;
						cerr << "REINITIALIZING PASSIVE LISTENING SOCKET: " << endl;
						cs = conn_list.begin();
						cs->connection.dest = c.dest;
						cs->connection.destport=c.destport;
						cs->state.SetState(SYN_RCVD);
						cerr <<"THIS CONNECTION IS " << c.dest << " " << c.destport << endl;
					}
				} else if (is_p_connected == 1) {

					cerr << "RECEIVED UNEXPECTED PACKET: " << p << endl;
				}
				else if (is_p_connected == 2)
				{
					cerr << "RECVIEVED ACK ON PASSIVE CLOSE FROM CLIENT" << endl;
				}


				cerr << "Current CTSM: " << cs->connection << endl;
				cerr << "Current State: " << stateNames[cs->state.GetState()] << endl;

				switch (cs->state.GetState()) {
				case LISTEN: 
					cerr << "IN LISTEN STATE" << endl;
					if ((IS_SYN(oldflags) && !IS_ACK(oldflags)) || IS_RST(oldflags)) {
						cerr << "\tpassive open..." << endl;
						cs->state.SetState(SYN_RCVD);
						cs->state.SetLastSent(seqnum);
						cs->state.SetSendRwnd(winsize);
						cerr << "\tbuilding SYNACK packet" << endl;
						SET_SYN(flags);
						SET_ACK(flags);
						Packet newp = buildPacket(c, id, seqnum, acknum + 1, winsize, hlen, uptr, flags, "", 0);
						MinetSend(mux, newp);
						cerr << "\tpacket sent" << endl;
						cs->state.SetLastRecvd(acknum + 1);
					}
					cerr << "EXITING LISTEN STATE" << endl;
					break;
				case SYN_SENT: 
					cerr << "IN SYN_SENT STATE" << endl;
					if (IS_SYN(oldflags) && IS_ACK(oldflags)) {
						cerr << "\tactive open ACK" << endl;
						cs->state.SetState(ESTABLISHED);
						cerr << "\tbuilding ACK packet" << endl;
						SET_ACK(flags);
						Packet newp = buildPacket(c, id, seqnum, acknum + 1, winsize, hlen, uptr, flags, "", 0);
						MinetSend(mux, newp);
						cerr << "\tpacket sent" << endl;

						SockRequestResponse write(WRITE, 
								cs->connection, 
								data, 
								0, 
								EOK);
						MinetSend(sock, write);
						cerr << "SYN_SENT SOCK REQ: " << write << endl;
						cerr << "\tsocket response written" << endl;
						cs->state.SetLastRecvd(acknum + 1);
					} else if (IS_SYN(oldflags)) {

						cerr << "\tpassive open" << endl;
						cs->state.SetState(SYN_RCVD);
						cs->state.SetLastSent(seqnum);
						cs->state.SetSendRwnd(winsize);
						cerr << "\tbuilding SYN_ACK packet" << endl;
						SET_SYN(flags);
						SET_ACK(flags);
						Packet newp = buildPacket(c, id, seqnum, acknum + 1, winsize, hlen, uptr, flags, "", 0);
						MinetSend(mux, newp);
						cerr << "\tpacket sent" << endl;
						cs->state.SetLastRecvd(acknum + 1);
					}
					cerr << "EXITING SYN_SENT STATE" << endl;
					break;
				case SYN_RCVD: 
					cerr << "SYN_RCVD STATE" << endl;
					if (IS_ACK(oldflags) && !IS_PSH(oldflags)) {
						cerr << "\tpassive open ACK" << endl;
						cs->state.SetState(ESTABLISHED);
					} else if ((IS_SYN(oldflags) && !IS_ACK(oldflags)) || IS_RST(oldflags)) {
						cerr << "\tSYNACK dropped" << endl;
						cs->state.SetLastSent(seqnum);
						cs->state.SetSendRwnd(winsize);		    
						cerr << "\tbuilding SYNACK packet" << endl;
						SET_SYN(flags);
						SET_ACK(flags);
						Packet newp = buildPacket(c, id, seqnum, acknum + 1, winsize, hlen, uptr, flags, "", 0);
						MinetSend(mux, newp);
						cerr << "\tpacket sent" << endl;
						cs->state.SetLastRecvd(acknum + 1);
					}
					cerr << "EXITING SYN_RCVD STATE" << endl;
					break;
				case ESTABLISHED: 
					cerr << "ESTABLISHED STATE" << endl;
					if (IS_FIN(oldflags)) {
						cerr << endl << "\treceived FIN packet" << endl;
						cerr << "\tbuilding ACK packet" << endl;
						SET_FIN(flags);
						SET_ACK(flags);
						Packet newp = buildPacket(c, id, seqnum, acknum + 1, winsize, hlen, uptr, flags, "", 0);
						MinetSend(mux, newp);
						cs->state.SetState(CLOSE_WAIT);
						is_p_connected = 2;
						cerr << "\tpacket sent" << endl;
						SockRequestResponse close(CLOSE, 
								cs->connection, 
								data, 
								hlen,
								EOK); 
						MinetSend(sock, close);
						cerr << "EST SOCK CLOSE REQ: " << close << endl;
						cerr << "\tsocket closed" << endl;
						flags = 0;
						SET_FIN(flags);
						newp = buildPacket(c, id, seqnum, acknum + 1, winsize, hlen, uptr, flags, "", 0);
						MinetSend(mux, newp);
						cerr << "SENT LAST FIN PACKET" << endl;
						cs->state.SetLastRecvd(acknum + 1);
					} else if (IS_RST(oldflags)) {
						cerr << endl << "\treceived RST packet" << endl;
						cs->state.SetLastSent(seqnum);
						cs->state.SetSendRwnd(winsize);
						cerr << "\tbuilding SYN_ACK packet" << endl;
						SET_SYN(flags);
						SET_ACK(flags);
						Packet newp = buildPacket(c, id, seqnum, acknum + 1, winsize, hlen, uptr, flags, "", 0);
						MinetSend(mux, newp);
						cerr << "\tpacket sent" << endl;
						cs->state.SetLastRecvd(acknum + 1);
					} else {
						cerr << "\treceived data packet" << endl;
						unsigned short templen = 0;
						unsigned char temphlen = 0;

						ipl.GetTotalLength(templen);
						ipl.GetHeaderLength(temphlen);
						templen -= 4 * temphlen + tcphlen;
						data = p.GetPayload().ExtractFront(templen);
						cerr << "DATA: \n" << data << endl << endl;
						cs->connection.dest = c.dest;
						cs->connection.src = c.src;
						cerr << "CS DEST: " << cs->connection.dest << "\nC DEST: " << c.dest << endl;
						cs->connection.destport = c.destport;
						cs->connection.srcport = c.srcport;
						SockRequestResponse write(WRITE,
								cs->connection,
								data,
								templen,
								EOK);
						MinetSend(sock, write);
						cerr << "EST DATA WRITE REQ: " << write << endl;
						cerr << "\twrite to sock" << endl;
						SocksPending.push(write);
						cerr << "\tbuilding ACK packet" << endl;
						SET_ACK(flags);
						Packet newp = buildPacket(c, id, seqnum, acknum + templen, winsize, hlen, uptr, flags, "", 0);
						cs->state.SetLastRecvd(acknum + templen);
						cerr << "SENDING ACK PACKET: \n" << newp << endl;
						MinetSend(mux, newp);
					}
					cerr << "EXITING ESTABLISHED STATE" << endl;
					break;
				case FIN_WAIT1: 
					cerr << "FIN_WAIT1 STATE" << endl;
					if (IS_FIN(oldflags) && IS_ACK(oldflags)) {
						cerr << "\treceived FIN packet" << endl;
						cs->state.SetState(TIME_WAIT);
						cerr << "\tbuilding ACK packet" << endl;
						SET_ACK(flags);
						Packet newp = buildPacket(c, id, seqnum, acknum + 1, winsize, hlen, uptr, flags, "", 0);
						MinetSend(mux, newp);
						cerr << "\tpacket sent" << endl;
						cs->state.SetLastRecvd(acknum + 1);
					} else if (IS_ACK(oldflags)) {
						cerr << "received close ACK packet" << endl;
						cs->state.SetState(FIN_WAIT2);
						cs->state.SetLastRecvd(acknum);
					} else {
						cerr << "FIN_WAIT1 UNEXPECTED PACKET" << endl;
					}
					cerr << "EXITING FIN_WAIT1 STATE" << endl;
					break;
				case FIN_WAIT2: 
					cerr << "FIN_WAIT2 STATE" << endl;
					if (IS_FIN(oldflags  && !IS_PSH(oldflags))) {
						cerr << "\treceived FIN packet" << endl;
						cs->state.SetState(TIME_WAIT);
						cerr << "\tbuilding ACK packet" << endl;
						flags = 0;
						SET_ACK(flags);
						Packet newp = buildPacket(c, id, seqnum, acknum + 1, winsize, hlen, uptr, flags, "", 0);
						MinetSend(mux, newp);
						cerr << "\tpacket sent" << endl;
						cs->state.SetLastRecvd(acknum + 1);
					} else if (IS_PSH(oldflags)) {
						cerr << "---still getting PSH ACKs---" << endl;
						flags = 0;
						SET_ACK(flags);
						Packet newp = buildPacket(c, id, seqnum, acknum + 1, winsize, hlen, uptr, flags, "", 0);
						MinetSend(mux, newp);
						cs->state.SetState(TIME_WAIT);
						cs->state.SetLastRecvd(acknum + 1);
					}
					cerr << "EXITING FIN_WAIT2" << endl;
					break;
				case CLOSE_WAIT:
				{
					cerr << "CLOSE_WAIT STATE" << endl;
					if (IS_ACK) {
						swap(SocksPending, empty);
						cerr << "Connection closed!" << endl;
						cs->state.SetState(LAST_ACK);
					}
					cerr << "EXITING CLOSE_WAIT STATE" << endl;
					break;
				case LAST_ACK: {
					if (IS_ACK) {
						cerr << "LAST_ACK STATE" << endl;
						cs->connection.dest = 0;
						cs->connection.destport = 0;
						cerr << "connection: " << cs->connection.dest << cs->connection.destport << endl;
						is_p_connected = 0;
						is_first = 0;
						cerr << "CONNECTION STATUS: " << is_p_connected << endl;
						cs->state.SetState(CLOSED);
						cerr << "EXITING LAST_ACK STATE" << endl;
					}
				}

				}
				case CLOSED: {
					cerr << "IN THE CLOSED STATE: " << endl;
					cs->state.SetState(LISTEN);
					break;
				}
				case TIME_WAIT: {
					static int time_wait_count = 0;
					time_wait_count++;
					cerr << "IN THE TIME_WAIT STATE: " << endl;
					if (time_wait_count > 2) {
						cs->state.SetState(CLOSED);
					} else if (time_wait_count == 1) {
						SockRequestResponse close(CLOSE, 
								cs->connection, 
								data, 
								hlen,
								EOK); 
						MinetSend(sock, close);
						conn_list.clear();
					}
					break;
				}
				default:
				{
					cerr << "DEFAULT CASE" << endl;
					break;
				}
				}
			}
			/******************/
			/***** SOCKET *****/
			/******************/
			if (event.handle==sock) {
				cerr << endl << "IN SOCK HANDLER" << endl;
				SockRequestResponse s;
				MinetReceive(sock,s);
				cerr << "Received Socket Request:" << s << endl;

				ConnectionList<TCPState>::iterator cs = conn_list.FindMatching(s.connection);
				cerr << "Current CTSM: " << cs->connection << endl;
				cerr << "Current State: " << stateNames[cs->state.GetState()] << endl;


				if (cs == conn_list.end()  && !is_p_connected) {
					is_p_connected = 1;
					cerr << "SOCK CONNECTION WAS NOT IN LIST" << endl;
					cerr << "MAKING THE STATIC SOCKET FOR THE PASSIVE OPEN CASE" << endl;

					cs->state.SetState(CLOSED);
					TCPState *server = new TCPState(1, LISTEN, 5);
					ConnectionToStateMapping<TCPState> new_cs(s.connection, Time(), *server, false);
					conn_list.push_back(new_cs);
					cs = conn_list.FindMatching(s.connection);
					is_first = 2; //used for an initialization trigger
				}
				else if (cs != conn_list.end())
				{
					cerr << "SOCK CONNECTION WAS IN LIST" << endl;
					cerr << "Received Socket Request:" << s << endl;
				}

				Packet newp;
				unsigned int len = 0;
				unsigned int sending = 0;
				char *datachars = NULL;

				switch (s.type) {
				case CONNECT: {
					is_a_connected = 1;
					cerr << "SOCK CONNECT CASE" << endl;
					cerr << "\tactive open init" << endl;

					seqnum = rand() % 50000;
					cerr << "SOCK CONNECTION WAS NOT IN LIST" << endl;
					cerr << "MAKING THE STATIC SOCKET FOR THE ACTIVE OPEN CASE" << endl;
					cerr << "THE CONNECTION IS: " << s.connection << endl;

					TCPState *server = new TCPState(seqnum, SYN_SENT, 1);
					ConnectionToStateMapping<TCPState> new_cs(s.connection, Time()+2, *server, true);
					conn_list.push_back(new_cs);
					cs = conn_list.FindMatching(s.connection);
					cerr << "\tpacket sent" << endl;
					cerr << "\tbuilding SYN packet" << endl;
					SET_SYN(flags);
					newp = buildPacket(s.connection, id, seqnum, acknum, winsize, hlen, uptr, flags, "", 0);
					MinetSend(mux, newp);
					sleep(2);
					MinetSend(mux, newp);
					cerr << "\tpacket sent" << endl;

					SockRequestResponse res(STATUS, 
							cs->connection, 
							data, 
							0, 
							EOK);
					MinetSend(sock, res);
					cs->state.SetLastSent(seqnum);
					cs->state.SetLastRecvd(acknum);

					cs->state.SetState(SYN_SENT);
				}
				cerr << "EXITING SOCK CONNECT CASE" << endl;
				break;
				case ACCEPT: {
					cerr << "SOCK ACCEPT CASE" << endl;
					cerr << "\tpassive open init" << endl;
					cs->state.SetState(LISTEN);
					cerr << "\tset to LISTEN state" << endl;
				}
				cerr << "EXITING SOCK ACCEPT CASE" << endl;
				break;
				case STATUS: {
					cerr << "SOCK STATUS CASE" << endl;
					if (!SocksPending.empty()) {
						cerr << "\tPending socket requests found" << endl;
						SockRequestResponse res = SocksPending.front();
						SocksPending.pop();
						sending = res.bytes - s.bytes;
						if (sending != 0) {
							cerr << "\tfound different sock request" << endl;
							SockRequestResponse res(WRITE, 
									s.connection, 
									data.ExtractBack(sending), 
									sending, 
									EOK);
							MinetSend(sock, res);
							cerr << "\tsock response sent" << endl;
							SocksPending.push(res);
						}
					}
				}
				cerr << "EXITING SOCK STATUS CASE" << endl;
				break;
				case WRITE: 
					cerr << "SOCK WRITE CASE" << endl;
					if (cs->state.GetState() == ESTABLISHED) {
						cerr << "\tcurrently in ESTABLISHED state" << endl;
						acknum = cs->state.GetLastRecvd();
						len = s.data.GetSize();
						sending = 0;
						datachars = (char *) malloc(TCP_MAXIMUM_SEGMENT_SIZE + 1);
						SockRequestResponse res(STATUS, 
								s.connection, 
								data, 
								len, 
								EOK);
						MinetSend(sock, res);
						cerr << "\tresponse written to socket" << endl;
						while (len > 0) {
							memset(datachars, 0, TCP_MAXIMUM_SEGMENT_SIZE + 1);
							seqnum = cs->state.GetLastSent();
							if (len > TCP_MAXIMUM_SEGMENT_SIZE) { // MSS 
								sending = TCP_MAXIMUM_SEGMENT_SIZE;
								len -= TCP_MAXIMUM_SEGMENT_SIZE;
							} else {
								sending = len;
								len -= len;
							}

							data = s.data.ExtractFront(sending);
							data.GetData(datachars, sending, 0);

							newp = buildPacket(s.connection, id, seqnum, acknum, winsize, hlen, uptr, flags, datachars, sending);
							MinetSend(mux, newp);
							cerr << "\tsending data packet..." << endl;
							cs->state.SetLastSent(seqnum + sending);
						}
						free(datachars);
					}
					cerr << "EXITING SOCK WRITE CASE" << endl;
					break;
				case FORWARD: 
					cerr << "SOCK FORWARD CASE" << endl;
					break;
				case CLOSE: 
					cerr << "SOCK CLOSE CASE" << endl;
					if (cs->state.GetState() == ESTABLISHED) {
						cerr << "\tcurrently in ESTABLISHED state" << endl;
						cs->state.SetState(FIN_WAIT1);
						flags = 0;
						SET_FIN(flags);
						newp = buildPacket(s.connection, id, seqnum, acknum, winsize, hlen, uptr, flags, "", 0);
						MinetSend(mux, newp);
						cerr << "\tFIN packet sent" << endl;
						cerr << "EXITING SOCK CLOSE CASE" << endl;
						cs->state.SetLastRecvd(acknum + 1);
						swap(SocksPending, empty);
						continue;
					}
					else if (cs->state.GetState() == CLOSE_WAIT) {
						cerr << "\tcurrently in CLOSE_WAIT state" << endl;
						cs->state.SetState(LAST_ACK);
					}
					else {
						cerr << "\tunexpected state: " << cs->state.GetState() << endl;
					}
					break;
				default:
				{
					cerr << "ENTERED THE SOCK DEFAULT CASE" << endl;
					break;
				}
				}


			}
			if (event.eventtype == MinetEvent::Timeout) {
				cerr << "TIMOUT OCCURED" << endl;
				ConnectionList<TCPState>::iterator i = conn_list.begin();
				for (; i != conn_list.end(); ++i) {
					if ((*i).bTmrActive)
						cerr << *i << endl;
				}
			}
		}
	}
	return 0;
}

Packet buildPacket(Connection c, unsigned int id, unsigned int seqnum, unsigned int acknum, unsigned short winsize, unsigned char hlen, unsigned short urgptr, unsigned char flags, const char *data, size_t datalen) {
	cerr << "\n*****BUILDING PACKET*****" << endl;
	Packet p(data, datalen);
	IPHeader ih;
	TCPHeader th;

	ih.SetProtocol(IP_PROTO_TCP);
	ih.SetSourceIP(c.src);
	ih.SetDestIP(c.dest);
	ih.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH);
	ih.SetID(id);
	cerr << "\tAdding IP Header" << endl;
	p.PushFrontHeader(ih);

	th.SetDestPort(c.destport, p);
	th.SetSourcePort(c.srcport, p);
	th.SetSeqNum(seqnum, p);
	th.SetAckNum(acknum, p);
	th.SetWinSize(winsize, p);
	th.SetHeaderLen(hlen, p);
	th.SetUrgentPtr(urgptr, p);
	th.SetFlags(flags, p);
	cerr << "\tAdding TCP Header" << endl;
	p.PushBackHeader(th);
	cerr << "*****PACKET BUILT*****\n" << endl;
	return p;
}
