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

	return interfaceHandle;
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
	}

	return 0;
}