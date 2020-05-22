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

func CheckEnd(candidate, standard string) bool {
	if len(candidate) < len(standard) {
		return false
	} else {
		for i := 0; i < len(standard); i++ {
			if standard[len(standard) - 1 -i] != candidate[len(candidate) - 1 - i] {
				return false
			}
		}
		return true
	}
}
