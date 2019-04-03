#include <stdint.h>
#include <iostream>
#include <string>
#include <unordered_map>
#include <memory>
#include <signal.h>

#include <pcap.h>

#include "ethernet.hh"
#include "ip.hh"
#include "tcp.hh"

std::string pcapFileName;
std::string ipToFilter;

sig_atomic_t volatile ceaseCapture = FALSE;

std::unordered_map<Flow, std::shared_ptr<TcpStream>, FlowHash> flowHashMap;

char errorBuffer[PCAP_ERRBUF_SIZE];

void SignalHandler(int32_t signalNumber) {

	if (signalNumber == SIGINT) {

		ceaseCapture = TRUE;
	}
}

void ParseCommandLineArguments(int argc, char **argv) {

	for (int i{}; i < argc; i++) {

		if (strcmp(argv[i], "-f") == 0) {
			if (i + 1 < argc) {
				pcapFileName = argv[i + 1];
			}
			else {
				std::cout << "pcap file name required" << std::endl;
				std::cout << "usage [-s ip] [-o output directory] [-f pcap file name]\n" << std::endl;
				exit(-1);
			}
		}
		else if (strcmp(argv[i], "-o") == 0) {
			if (i + 1 < argc) {
				DWORD fileType = GetFileAttributesA(argv[i + 1]);

				if (fileType == INVALID_FILE_ATTRIBUTES || (fileType & FILE_ATTRIBUTE_DIRECTORY) == 0) {

					std::cout << "failed to access directory: " << argv[i + 1] <<
						         " using current directory " << std::endl;

					HttpTracer::outputDirectory = "";
				}
				else {

					HttpTracer::outputDirectory = argv[i + 1];
				}
			}
			else {
				std::cout << "output directory name required" << std::endl;
				std::cout << "usage [-s ip] [-o output directory] [-f pcap file name]\n" << std::endl;
				exit(-2);
			}
		}
		else if (strcmp(argv[i], "-s") == 0) {
			if (i + 1 < argc) {
				ipToFilter = argv[i + 1];
			}
			else {
				std::cout << "ip address required" << std::endl;
				std::cout << "usage [-s ip] [-o output directory] [-f pcap file name]\n" << std::endl;
				exit(-2);
			}
		}
	}
}

void ApplyFilter(pcap_t *pcapHandle) {

	char filterExp[23] = { 0 };
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct bpf_program fp;

	sprintf_s(filterExp, "ip host %s", ipToFilter.c_str());

	char *dev = pcap_lookupdev(errorBuffer);

	if (dev == NULL) {

		std::cout << "faield to look up dev" << std::endl;
		exit(-5);
	}

	if (pcap_lookupnet(dev, &net, &mask, errorBuffer) == -1) {

		std::cout << "failed to look up net" << std::endl;
		exit(-6);
	}

	if (pcap_compile(pcapHandle, &fp, filterExp, 0, net) == -1) {

		std::cout << "couldn't parse filter " << filterExp << ": " << pcap_geterr(pcapHandle) << std::endl;
		exit(-7);
	}

	if (pcap_setfilter(pcapHandle, &fp) == -1) {

		std::cout << "couldn't install filter " << filterExp << ": " << pcap_geterr(pcapHandle) << std::endl;
		exit(-8);
	}
}

pcap_t *ObtainOfflinePcapHandle() {

	pcap_t *pcapFileHandle = pcap_open_offline(pcapFileName.c_str(), errorBuffer);

	return pcapFileHandle;
}

pcap_t *ObtainOnlinePcapHandle() {

	pcap_if_t *networkInterfaces;
	pcap_if_t *selectedInterface;
	pcap_t *interfaceHandle = NULL;

	if (pcap_findalldevs(&networkInterfaces, errorBuffer) == -1) {

		std::cout << "failed to retreive all interfaces" << std::endl;
		return NULL;
	}

	int interfacesCount{ 0 };

	for (selectedInterface = networkInterfaces; selectedInterface != NULL; selectedInterface = selectedInterface->next) {

		std::cout << std::endl;
		std::cout << ++interfacesCount << "." << selectedInterface->name;

		if (strlen(selectedInterface->description))
			std::cout << "-- " << selectedInterface->description << std::endl;
	}

	int interfaceNumber{ -1 };

	std::cout << "Enter desired interface number between 1 and " << interfacesCount << ":";
	std::cin >> interfaceNumber;

	if (interfaceNumber < 1 || interfaceNumber > interfacesCount)
	{
		std::cout << std::endl;
		std::cout << "Interface number out of range." << std::endl;

		pcap_freealldevs(networkInterfaces);

		return NULL;
	}

	selectedInterface = networkInterfaces;

	for (interfacesCount = 0; interfacesCount < interfaceNumber - 1; interfacesCount++)
		selectedInterface = selectedInterface->next;

	interfaceHandle = pcap_open(selectedInterface->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errorBuffer);

	pcap_freealldevs(networkInterfaces);

	return interfaceHandle;
}

void CaptureTraffic(pcap_t *pcapHandle) {

	struct pcap_pkthdr  *packetHeader;
	const unsigned char *packetData;
	int ret = 0;

	const struct EthernetHeader *ethernet;
	const struct IpHeader *ip;
	const struct TcpHeader *tcp; /* The TCP header */
	uint32_t sizeIp;
	uint32_t sizeTcp;

	signal(SIGINT, SignalHandler);

	std::cout << "capture session started (use CTRL-C to stop) ..." << std::endl;

	while (((ret = pcap_next_ex(pcapHandle, &packetHeader, &packetData)) >= 0) && ceaseCapture == FALSE) {

		if (ret == -1) {

			std::cout << "error occured while reading packet: " << pcap_geterr(pcapHandle);
			continue;
		}
		if (ret == 0)
			continue;

		ethernet = (struct EthernetHeader*)(packetData);

		ip = (struct IpHeader*)(packetData + SIZE_ETHERNET);
		sizeIp = IP_HL(ip) * 4;

		if (ip->ipP == 6) {

			tcp = (struct TcpHeader*)(packetData + SIZE_ETHERNET + sizeIp);
			sizeTcp = TH_OFF(tcp) * 4;

			Flow flowKey;
			flowKey.srcAddr = ntohl(ip->ipSrc.S_un.S_addr);
			flowKey.dstAddr = ntohl(ip->ipDst.S_un.S_addr);
			flowKey.protocol = ip->ipP;
			flowKey.srcPort = ntohs(tcp->thSport);
			flowKey.dstPort = ntohs(tcp->thDport);
			flowKey.ipTotalLen = ntohs(ip->ipLen);
			flowKey.payloadLen = flowKey.ipTotalLen - (sizeIp + sizeTcp);
			flowKey.payload = packetData + (SIZE_ETHERNET + sizeIp + sizeTcp);

			auto it = flowHashMap.find(flowKey);

			if (it == flowHashMap.end()) {

				if (tcp->thFlags & TH_SYN) {

					auto tcpStream = std::make_shared<TcpStream>(flowKey);

					tcpStream->Trace(flowKey, tcp);

					if (tcpStream->GetState() == TCP_CONNECTION_STATE::SYN) {

						flowHashMap.insert(std::make_pair(flowKey, tcpStream));
					}

				}
				else {

				}
			}
			else {

				auto tcpStream = it->second;
				tcpStream->Trace(flowKey, tcp);

				if (tcpStream->GetState() == TCP_CONNECTION_STATE::CLOSED) {

					flowHashMap.erase(it);
				}
			}
		}
	}

	std::cout << "capture traffic ended (exiting...)" << std::endl;
	std::cout << "press any key to exit (...)" << std::endl;
	getchar();

	return;
}

int main(int argc, char **argv) {

	ParseCommandLineArguments(argc, argv);

	pcap_t *pcapHandle = NULL;

	if (pcapFileName.size() > 0) {

		pcapHandle = ObtainOfflinePcapHandle();

		if (pcapHandle == NULL) {

			std::cout << "failed to open pcap file: " << pcapFileName << std::endl;
			exit(-3);
		}
	}
	else {

		pcapHandle = ObtainOnlinePcapHandle();

		if (pcapHandle == NULL) {

			std::cout << "failed to open interface: " << std::endl;
			exit(-4);
		}
	}

	if (ipToFilter.size() > 0) {

		ApplyFilter(pcapHandle);
	}

	CaptureTraffic(pcapHandle);

	return 0;
}