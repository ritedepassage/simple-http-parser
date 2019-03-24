#include <stdint.h>
#include <iostream>

#include <pcap.h>

std::string pcapFileName;
std::string captureDirectory;
std::string ipToFilter;

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

int main(int argc, char **argv) {

	ParseCommandLineArguments(argc, argv);

	return 0;
}