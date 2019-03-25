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

	}

	return 0;
}