package analyser

import (
	"fmt"
	"github.com/ammario/ipisp"
	"log"
	"net"
)

func GetAsByIp(ip string) {
	client, err := ipisp.NewDNSClient()
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	resp, err := client.LookupIP(net.ParseIP(ip))
	fmt.Printf("%v", resp.Name.Raw)
}

