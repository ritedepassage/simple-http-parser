#include <stdint.h>
#include <iostream>
#include <string>

#include <pcap.h>

std::string pcapFileName;
std::string captureDirectory;
std::string ipToFilter;

char errorBuffer[PCAP_ERRBUF_SIZE];

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
				captureDirectory = argv[i + 1];
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

	while (((ret = pcap_next_ex(pcapHandle, &packetHeader, &packetData)) >= 0)) {

		if (ret == -1) {

			std::cout << "error occured while reading packet: " << pcap_geterr(pcapHandle);
			continue;
		}
		if (ret == 0)
			continue;
	}
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