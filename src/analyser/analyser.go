package analyser

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)



type StatsForSpecificDecoy struct {
	numSuccesses int
	numFailures int
	failureRate float64
}

type AggregatedCountryStats struct {
	decoyStatsForThisCountry map[string]*StatsForSpecificDecoy // decoy ip -> stats
}

type Connection struct {
	connectionType string
	clientIP string
	decoyIP string
	clientCountry string
}

type Analyser struct {
	countryStats map[string]*AggregatedCountryStats // Country name -> stats
	decoyStats map[string]*StatsForSpecificDecoy // Decoy ip -> stats
	ipToHostname map[string]string
	countryChannel chan Connection
	decoyChannel chan Connection
}



func InitAnalyser() *Analyser{
	al := new(Analyser)
	al.countryStats = make(map[string]*AggregatedCountryStats)
	al.decoyStats = make(map[string]*StatsForSpecificDecoy)
	al.ipToHostname = make(map[string]string)
	al.countryChannel = make(chan Connection, 64)
	al.decoyChannel = make(chan Connection, 64)
	return al
}

const ShellToUse = "bash"

func Shellout(command string) (error, string, string) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.Command(ShellToUse, "-c", command)
	cmd.Dir = "decoy-lists"
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return err, stdout.String(), stderr.String()
}

func ShelloutParentDir(command string) (error, string, string) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.Command(ShellToUse, "-c", command)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return err, stdout.String(), stderr.String()
}

func (al *Analyser) FetchLog() {
	err, currentDir, stderr := ShelloutParentDir("pwd")
	println(err, currentDir, stderr)
	yesterdayDate := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	targetFileName := "tapdance-" + yesterdayDate + ".log.gz"
	SCPCommand := "sshpass -p \"8416Xuan-greed\" scp -r yxluo@128.138.97.190:/var/log/logstash/refraction/tapdance/"
	SCPCommand += targetFileName
	SCPCommand += " "
	SCPCommand += currentDir
	err, _, stderr = ShelloutParentDir(SCPCommand)
	if err != nil || stderr != "" {
		log.Fatal(err)
	}
	err, _, stderr = ShelloutParentDir("gunzip " + targetFileName)
	return
}

func (al *Analyser) ReadLog() {
	yesterdayDate := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	targetFileName := "tapdance-" + yesterdayDate + ".log"
	file, _ := os.Open(targetFileName)
	decoder := json.NewDecoder(file)
	go func() {
		for true {
			v := new(map[string]interface{})
			err := decoder.Decode(v)
			if err != nil {
				return
			} else {
				go al.ProcessMessage(v)
			}
		}
		time.Sleep(10 * time.Second)
		close(al.countryChannel)
		close(al.decoyChannel)
	} ()

}

func (al * Analyser) ProcessDecoyChannel(terminationChannel1 chan bool) {
	for connection := range al.countryChannel {

		if _, exist := al.decoyStats[connection.decoyIP]; !exist {
			al.decoyStats[connection.decoyIP] = new(StatsForSpecificDecoy)
		}
		if connection.connectionType == "newflow" {
			al.decoyStats[connection.decoyIP].numSuccesses++
		} else {
			al.decoyStats[connection.decoyIP].numFailures++
		}

	}
	fmt.Println("Decoy Channel closed")
	close(terminationChannel1)
}

func (al *Analyser) ProcessCountryChannel(terminationChannel2 chan bool) {
	for connection := range al.countryChannel {
		if _, exist := al.countryStats[connection.clientCountry]; !exist {
			al.countryStats[connection.clientCountry] = new(AggregatedCountryStats)
			al.countryStats[connection.clientCountry].decoyStatsForThisCountry = make(map[string]*StatsForSpecificDecoy)
		}

		if _, exist := al.countryStats[connection.clientCountry].decoyStatsForThisCountry[connection.decoyIP]; !exist {
			al.countryStats[connection.clientCountry].decoyStatsForThisCountry[connection.decoyIP] = new(StatsForSpecificDecoy)
		}

		if connection.connectionType == "newflow" {
			al.countryStats[connection.clientCountry].decoyStatsForThisCountry[connection.decoyIP].numSuccesses++
		} else {
			al.countryStats[connection.clientCountry].decoyStatsForThisCountry[connection.decoyIP].numFailures++
		}
	}
	fmt.Println("Country Channel closed")
	close(terminationChannel2)
}

func (al *Analyser) ProcessMessage(v *map[string]interface{}) {
	if _, exist := (*v)["system"]; exist {
		system := (*v)["system"].(map[string]interface{})
		if _, exist := system["syslog"]; exist {
			syslog := system["syslog"].(map[string]interface{})
			if _, exist := syslog["message"]; exist {
				message := syslog["message"].(string)
				connection := ProcessMessage(message)
				if connection.connectionType != "" {
					fmt.Printf("%v %v %v\n", connection.connectionType, connection.clientIP, connection.decoyIP)
					al.decoyChannel <- connection
					al.countryChannel <- connection
				}
			}
		}
	}
}

func (al *Analyser) ReadDecoyList() {
	err, stdout, _ := Shellout("git pull")
	err, stdout, _ = Shellout("ls")
	files := strings.Split(stdout, "\n")
	sampleName := "-decoys.txt"
	fileNameOfLatestDecoyList := ""

	for _, item := range files {
		if CheckEnd(item, sampleName) {
			fileNameOfLatestDecoyList = item
		}
	}

	err, stdout, _ = Shellout("ls")
	_ = os.Chdir("decoy-lists")
	f, err := os.Open(fileNameOfLatestDecoyList)
	defer f.Close()
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(f)
	scanner.Scan()

	for {
		scanner.Scan()
		row := strings.Split(scanner.Text(), string(','))
		if scanner.Text() == "" {
			break
		} else {
			ip := row[0]
			hostname := row[1]
			al.ipToHostname[ip] = hostname
		}
	}
	_ = os.Chdir("..")
}

func (al *Analyser)ComputeFailureRateForCountry() {
	for _, statsForEachCountry := range al.countryStats {
		for _,statsForEachDecoy := range statsForEachCountry.decoyStatsForThisCountry {
			statsForEachDecoy.failureRate = float64(statsForEachDecoy.numFailures) / (float64(statsForEachDecoy.numFailures) + float64(statsForEachDecoy.numSuccesses))
		}
	}
}

func (al *Analyser) ComputeFailureRateForDecoy() {
	for _, statsForEachDecoy := range al.decoyStats {
		statsForEachDecoy.failureRate = float64(statsForEachDecoy.numFailures) / (float64(statsForEachDecoy.numFailures) + float64(statsForEachDecoy.numSuccesses))
	}
}

func (al *Analyser) PrintDecoyReports(numberOfDecoysToList, sampleSizeThreshold int) {
	var cumulativeSuccesses int
	var cumulativeFailures int
	for _, statsForEachDecoy := range al.decoyStats {
		cumulativeFailures += statsForEachDecoy.numFailures
		cumulativeSuccesses += statsForEachDecoy.numSuccesses
	}
	fmt.Printf("\n\nThe average failure rate of all decoys in the past hour is %v \n", float64(cumulativeFailures)/float64(cumulativeFailures + cumulativeSuccesses) )

	type kv struct {
		DecoyIP string
		DecoyFailureRate float64
		SampleSize int
	}

	var sortingSlice []kv
	for key,value := range al.decoyStats {
		sortingSlice = append(sortingSlice, kv{key, value.failureRate, value.numSuccesses + value.numFailures})
	}

	sort.Slice(sortingSlice, func(i, j int) bool {
		if sortingSlice[i].DecoyFailureRate == sortingSlice[j].DecoyFailureRate {
			return sortingSlice[i].SampleSize >  sortingSlice[j].SampleSize
		} else {
			return sortingSlice[i].DecoyFailureRate < sortingSlice[j].DecoyFailureRate
		}
	})

	fmt.Printf("\nThe top %v decoys with at least %v connections in the past hour are:\n\n", numberOfDecoysToList, sampleSizeThreshold)
	fmt.Printf("\t %v \t %v \t %v \t %v \n", "Detector IP", "Failure Rate", "Sample Size", "Hostname")
	var count int
	for i := 0; i < len(sortingSlice) && count < numberOfDecoysToList; i++ {
		if sortingSlice[i].SampleSize >= sampleSizeThreshold {
			count++
			domain := "Unknown"
			if _, found := al.ipToHostname[sortingSlice[i].DecoyIP]; found {
				domain = al.ipToHostname[sortingSlice[i].DecoyIP]
			}
			for len(sortingSlice[i].DecoyIP) < 15 {
				sortingSlice[i].DecoyIP += " "
			}
			fmt.Printf("\t %v \t %v \t %v \t\t %v \n", sortingSlice[i].DecoyIP, math.Floor(sortingSlice[i].DecoyFailureRate*100)/100, sortingSlice[i].SampleSize, domain)
		}
	}

	fmt.Printf("\n\nThe bottom %v decoys with at least %v connections in the past hour are:\n\n", numberOfDecoysToList, sampleSizeThreshold)
	fmt.Printf("\t %v \t %v \t %v \t %v \n", "Detector IP", "Failure Rate", "Sample Size", "Hostname")
	count = 0
	for i := len(sortingSlice) - 1; i >= 0 && count < numberOfDecoysToList; i-- {
		if sortingSlice[i].SampleSize >= sampleSizeThreshold {
			count++
			domain := "Unknown"
			if _, found := al.ipToHostname[sortingSlice[i].DecoyIP]; found {
				domain = al.ipToHostname[sortingSlice[i].DecoyIP]
			}
			for len(sortingSlice[i].DecoyIP) < 15 {
				sortingSlice[i].DecoyIP += " "
			}
			fmt.Printf("\t %v \t %v \t %v \t\t %v \n", sortingSlice[i].DecoyIP, math.Floor(sortingSlice[i].DecoyFailureRate*100)/100, sortingSlice[i].SampleSize, domain)
		}
	}

}

func (al *Analyser) PrintDecoyReportFor(country string, numberOfDecoysToList, sampleSizeThreshold int) {
	if _, exist := al.countryStats[country]; !exist {
		return
	}

	var cumulativeSuccesses int
	var cumulativeFailures int
	for _, statsForEachDecoy := range al.countryStats[country].decoyStatsForThisCountry {
		cumulativeFailures += statsForEachDecoy.numFailures
		cumulativeSuccesses += statsForEachDecoy.numSuccesses
	}
	fmt.Printf("\n\nThe average failure rate for %v in the past hour is %v \n", country, float64(cumulativeFailures)/float64(cumulativeFailures + cumulativeSuccesses) )

	type kv struct {
		DecoyIP string
		DecoyFailureRate float64
		SampleSize int
	}

	var sortingSlice []kv
	for key,value := range al.countryStats[country].decoyStatsForThisCountry {
		sortingSlice = append(sortingSlice, kv{key, value.failureRate, value.numSuccesses + value.numFailures})
	}

	sort.Slice(sortingSlice, func(i, j int) bool {
		if sortingSlice[i].DecoyFailureRate == sortingSlice[j].DecoyFailureRate {
			return sortingSlice[i].SampleSize >  sortingSlice[j].SampleSize
		} else {
			return sortingSlice[i].DecoyFailureRate < sortingSlice[j].DecoyFailureRate
		}
	})

	fmt.Printf("\nThe top %v decoys for %v with at least %v connections in the past hour are:\n\n", numberOfDecoysToList, country, sampleSizeThreshold)
	fmt.Printf("\t %v \t %v \t %v \t %v \n", "Detector IP", "Failure Rate", "Sample Size", "Hostname")
	var count int
	for i := 0; i < len(sortingSlice) && count < numberOfDecoysToList; i++ {
		if sortingSlice[i].SampleSize >= sampleSizeThreshold {
			count++
			domain := "Unknown"
			if _, found := al.ipToHostname[sortingSlice[i].DecoyIP]; found {
				domain = al.ipToHostname[sortingSlice[i].DecoyIP]
			}
			for len(sortingSlice[i].DecoyIP) < 15 {
				sortingSlice[i].DecoyIP += " "
			}
			fmt.Printf("\t %v \t %v \t %v \t\t %v \n", sortingSlice[i].DecoyIP, math.Floor(sortingSlice[i].DecoyFailureRate*100)/100, sortingSlice[i].SampleSize, domain)
		}
	}

	fmt.Printf("\n\nThe bottom %v decoys for %v with at least %v connections in the past hour are:\n\n", numberOfDecoysToList, country, sampleSizeThreshold)
	fmt.Printf("\t %v \t %v \t %v \t %v \n", "Detector IP", "Failure Rate", "Sample Size", "Hostname")
	count = 0
	for i := len(sortingSlice) - 1; i >= 0 && count < numberOfDecoysToList; i-- {
		if sortingSlice[i].SampleSize >= sampleSizeThreshold {
			count++
			domain := "Unknown"
			if _, found := al.ipToHostname[sortingSlice[i].DecoyIP]; found {
				domain = al.ipToHostname[sortingSlice[i].DecoyIP]
			}
			for len(sortingSlice[i].DecoyIP) < 15 {
				sortingSlice[i].DecoyIP += " "
			}
			fmt.Printf("\t %v \t %v \t %v \t\t %v \n", sortingSlice[i].DecoyIP, math.Floor(sortingSlice[i].DecoyFailureRate*100)/100, sortingSlice[i].SampleSize, domain)
		}
	}
}


func ProcessMessage(message string) (Connection) {
	splitMessage := strings.Split(message, " ")
	var connection Connection

	if len(splitMessage) > (7 + 3) {
		if splitMessage[7] == "newflow" {
			connection.connectionType = "newflow"
			connection.clientIP = strings.Split(splitMessage[7 + 1], ":")[0]
			connection.decoyIP = strings.Split(splitMessage[7 + 3], ":")[0]
		} else if splitMessage[7] == "faileddecoy" {
			connection.connectionType = "faileddecoy"
			connection.clientIP = strings.Split(splitMessage[7 + 1], ":")[0]
			connection.decoyIP = strings.Split(splitMessage[7 + 3], ":")[0]
		}
	}

	if connection.clientIP != "" {
		connection.clientCountry = GetCountryByIp(connection.clientIP)
	}

	return connection
}