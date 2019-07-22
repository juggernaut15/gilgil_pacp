#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}


void print_mac(const u_char* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const u_char* ip) {
    printf("%d %d %d %d\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(const u_char* port) {
    printf("%d\n", (uint16_t(port[0]*256)) + port[1]);		// port[0] 는 uint8_t이기 때문에 그런데 할 필요없다.=> eax(32bit 레지스터) => 타입맞춰준다
}

void print_data(const u_char* data){
    int i =0;
    while(i<10 && data){

    }
}

int tcph_length(const u_char* p){
    return (p[14+20+12]&0xF0)/4;
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }


  char* dev = argv[1];              // device name = eth0
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {



    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    printf("Dmac ");
    print_mac(packet);
    printf("Smac ");
    print_mac(packet+6);

    if((u_int16_t)packet[12]==8 && (u_int16_t)packet[13]==0){
        printf("S-ip ");
        print_ip(packet+14+12);
        printf("D-ip ");
        print_ip(packet+14+12+4);
        if((int)packet[14+9]==6){
            printf("S-port ");
            print_port(packet+14+20);
            printf("D-port ");
            print_port(packet+14+22);

            int l = packet[14+2]*256+packet[14+3]-tcph_length(packet)-20;
            int i=0;
            if(l>0){
                while(i<10 && i<l){
                    printf("%02x ",packet[14+20+tcph_length(packet)+i] );
                    i++;
                }
                printf("\n");
            }

        }

    }
  }

  pcap_close(handle);
  return 0;
}
