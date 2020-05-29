package analyser

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
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
	averageFailureRate float64
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
	completeDecoyList []string
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
	yesterdayDate := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	targetFileName := "tapdance-" + yesterdayDate + ".log.gz"
	SCPCommand := "sshpass scp -r yxluo@128.138.97.190:/var/log/logstash/refraction/tapdance/"
	SCPCommand += targetFileName
	SCPCommand += " "
	SCPCommand += currentDir
	fmt.Printf("Retrieving %v from Greed ...\n", targetFileName)
	err, _, stderr = ShelloutParentDir(SCPCommand)
	if err != nil || stderr != "" {
		log.Fatal(err)
	}
	fmt.Printf("Decompressing %v ...\n", targetFileName)
	err, _, stderr = ShelloutParentDir("gunzip " + targetFileName)
	return
}

func (al *Analyser) ReadLog() {
	yesterdayDate := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	targetFileName := "tapdance-" + yesterdayDate + ".log"
	fmt.Printf("Parsing %v ...\n", targetFileName)

	file, _ := os.Open(targetFileName)
	decoder := json.NewDecoder(file)
	go func() {
		for true {
			v := new(map[string]interface{})
			err := decoder.Decode(v)
			if err != nil {
				break
			} else {
				go al.ProcessMessage(v)
			}
		}

		fmt.Printf("Finished parsing %v, closing channels ...\n", targetFileName)
		time.Sleep(10 * time.Second)
		close(al.countryChannel)
		close(al.decoyChannel)
		fmt.Printf("Removing %v ...\n", targetFileName)
		_, _, _ = ShelloutParentDir("rm -rf " + targetFileName)
	} ()

}

func (al * Analyser) ProcessDecoyChannel(terminationChannel1 chan bool) {
	for connection := range al.decoyChannel {

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
					al.decoyChannel <- connection
					al.countryChannel <- connection
				}
			}
		}
	}
}

func (al *Analyser) ReadDecoyList() {
	println("Pulling decoy-lists from github ...")
	err, stdout, _ := ShelloutParentDir("git clone git@github.com:refraction-networking/decoy-lists.git")
	err, stdout, _ = Shellout("ls")
	files := strings.Split(stdout, "\n")
	sampleName := "-decoys.txt"
	fileNameOfLatestDecoyList := ""

	for _, item := range files {
		if CheckEnd(item, sampleName) {
			fileNameOfLatestDecoyList = item
		}
	}

	fmt.Printf("Reading %v ...\n", fileNameOfLatestDecoyList)
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
		al.completeDecoyList = append(al.completeDecoyList, scanner.Text())
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
	println("Cleaning up decoy-lists ...")
	err, stdout, _ = ShelloutParentDir("rm -rf decoy-lists")
}

func (al *Analyser)ComputeFailureRateForCountry(terminationChannel chan bool) {
	println("Computing failure rate for each country ...")

	for _, statsForEachCountry := range al.countryStats {
		for _,statsForEachDecoy := range statsForEachCountry.decoyStatsForThisCountry {
			statsForEachDecoy.failureRate = float64(statsForEachDecoy.numFailures) / (float64(statsForEachDecoy.numFailures) + float64(statsForEachDecoy.numSuccesses))
		}
	}
	println("Finished computing failure rate for each country ...")
	close(terminationChannel)
}

func (al *Analyser) ComputeFailureRateForDecoy(terminationChannel chan bool) {
	println("Computing failure rate for each decoy ...")

	for _, statsForEachDecoy := range al.decoyStats {
		statsForEachDecoy.failureRate = float64(statsForEachDecoy.numFailures) / (float64(statsForEachDecoy.numFailures) + float64(statsForEachDecoy.numSuccesses))
	}
	println("Finished computing failure rate for each decoy ...")
	close(terminationChannel)
}

func (al *Analyser) PrintDecoyReports(numberOfDecoysToList, sampleSizeThreshold int) {
	var cumulativeSuccesses int
	var cumulativeFailures int
	for _, statsForEachDecoy := range al.decoyStats {
		cumulativeFailures += statsForEachDecoy.numFailures
		cumulativeSuccesses += statsForEachDecoy.numSuccesses
	}
	fmt.Printf("\n\nThe average failure rate of all decoys in the past day is %v \n", float64(cumulativeFailures)/float64(cumulativeFailures + cumulativeSuccesses) )

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

	fmt.Printf("\nThe top %v decoys with at least %v connections in the past day are:\n\n", numberOfDecoysToList, sampleSizeThreshold)
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
			fmt.Printf("\t %v \t %v \t %v \t\t %v \n", sortingSlice[i].DecoyIP, sortingSlice[i].DecoyFailureRate, sortingSlice[i].SampleSize, domain)
		}
	}

	fmt.Printf("\n\nThe bottom %v decoys with at least %v connections in the past day are:\n\n", numberOfDecoysToList, sampleSizeThreshold)
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
			fmt.Printf("\t %v \t %v \t %v \t\t %v \n", sortingSlice[i].DecoyIP, sortingSlice[i].DecoyFailureRate, sortingSlice[i].SampleSize, domain)
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
	fmt.Printf("\n\nThe average failure rate for %v in the past day is %v \n", country, float64(cumulativeFailures)/float64(cumulativeFailures + cumulativeSuccesses) )

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

	fmt.Printf("\nThe top %v decoys for %v with at least %v connections in the past day are:\n\n", numberOfDecoysToList, country, sampleSizeThreshold)
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
			fmt.Printf("\t %v \t %v \t %v \t\t %v \n", sortingSlice[i].DecoyIP, sortingSlice[i].DecoyFailureRate, sortingSlice[i].SampleSize, domain)
		}
	}

	fmt.Printf("\n\nThe bottom %v decoys for %v with at least %v connections in the past day are:\n\n", numberOfDecoysToList, country, sampleSizeThreshold)
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
			fmt.Printf("\t %v \t %v \t %v \t\t %v \n", sortingSlice[i].DecoyIP, sortingSlice[i].DecoyFailureRate, sortingSlice[i].SampleSize, domain)
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

type CoolDown struct {
	daysRemaining int
	NextBenchDays int
}

func (al *Analyser) CalculateAverageFailureRateForEachCountry() {
	for countryName, countryInfo  := range al.countryStats {
		var cumulativeSuccesses int
		var cumulativeFailures int
		for _, statsForEachDecoy := range countryInfo.decoyStatsForThisCountry {
			cumulativeFailures += statsForEachDecoy.numFailures
			cumulativeSuccesses += statsForEachDecoy.numSuccesses
		}
		countryInfo.averageFailureRate = float64(cumulativeFailures)/float64(cumulativeFailures + cumulativeSuccesses)
		fmt.Printf("The average failure rate for %v in the past day is %v \n", countryName, countryInfo.averageFailureRate)
	}

}

func (al *Analyser) UpdateActiveDecoyList() {

	/*
	Benching Criteria:
		Failure Rate > daily average for each country + 0.05
	 */

	const amnesty = 0.05

	for countryCode, countryInfo := range al.countryStats {
		coolDownStats := make(map[string]CoolDown)
		benchedFile, err := os.Open("./list/" + countryCode + "_Benched.csv")
		if err == nil { // There exist benched decoys for this country
			scanner := bufio.NewScanner(benchedFile)
			for scanner.Scan() {
				line := strings.Split(scanner.Text(), ",")
				IP := line[0]
				daysRemaining, _ := strconv.Atoi(line[1])
				NextBenchDays, _ := strconv.Atoi(line[2])
				coolDownStats[IP] = CoolDown{daysRemaining: daysRemaining, NextBenchDays: NextBenchDays}
			}

			for key, value := range coolDownStats {
				if value.daysRemaining == 0 {
					value.NextBenchDays--
					if value.NextBenchDays <= 0 {
						delete(coolDownStats, key)
					}
				} else {
					value.daysRemaining--
				}
			}
			benchedFile.Close()
		}



		// bench bad decoys
		for decoyIP, DecoyInfo := range countryInfo.decoyStatsForThisCountry {
			if DecoyInfo.failureRate > countryInfo.averageFailureRate + amnesty {
				if value, exist := coolDownStats[decoyIP]; exist {
					value.daysRemaining = value.NextBenchDays
					value.NextBenchDays *= 2
					coolDownStats[decoyIP] = value
				} else {
					coolDownStats[decoyIP] = CoolDown{
						daysRemaining: 1,
						NextBenchDays: 2,
					}
				}
			}
		}

		//write benching info to file
		_, _, _ = ShelloutParentDir("rm ./list/" + countryCode + "_Benched.csv")
		if len(coolDownStats) != 0 {
			benchedFile, _ = os.Create("./list/" + countryCode + "_Benched.csv")
			benchWriter := bufio.NewWriter(benchedFile)
			for decoyIP, coolDownInfo := range coolDownStats {
				_, _ = fmt.Fprintf(benchWriter, "%v,%v,%v\n", decoyIP, coolDownInfo.daysRemaining, coolDownInfo.NextBenchDays)
			}
			_ = benchWriter.Flush()
			benchedFile.Close()
		}

		//write active decoys to file
		_, _, _ = ShelloutParentDir("rm ./list/" + countryCode + "_Active.txt")
		activeFile, _ := os.Create("./list/" + countryCode + "_Active.txt")
		activeWriter := bufio.NewWriter(activeFile)
		for _, item := range al.completeDecoyList {
			if _, exist := coolDownStats[strings.Split(item, ",")[0]]; !exist {
				_, _ = fmt.Fprintf(activeWriter, item + "\n")
			} else {
				if coolDownStats[strings.Split(item, ",")[0]].daysRemaining == 0 {
					_, _ = fmt.Fprintf(activeWriter, item + "\n")
				}
			}
		}
		_ = activeWriter.Flush()
		activeFile.Close()
		fmt.Printf("%v decoys benched(%v of all available decoys) for %v\n", len(coolDownStats), float64(len(coolDownStats))/float64(len(al.ipToHostname)), countryCode)
	}
}



func (al *Analyser) WriteDecoyReportFor(filename, country string, numberOfDecoysToList, sampleSizeThreshold int) {
	if _, exist := al.countryStats[country]; !exist {
		return
	}

	var cumulativeSuccesses int
	var cumulativeFailures int
	for _, statsForEachDecoy := range al.countryStats[country].decoyStatsForThisCountry {
		cumulativeFailures += statsForEachDecoy.numFailures
		cumulativeSuccesses += statsForEachDecoy.numSuccesses
	}
	averageFailureRate := float64(cumulativeFailures)/float64(cumulativeFailures + cumulativeSuccesses)
	f, _ := os.Create(filename + ".txt")
	w := bufio.NewWriter(f)
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

	numberOfUnknownDomain := len(sortingSlice)
	for i := 0; i < len(sortingSlice); i++ {
		domain := "Unknown"
		if _, found := al.ipToHostname[sortingSlice[i].DecoyIP]; found {
			domain = al.ipToHostname[sortingSlice[i].DecoyIP]
			numberOfUnknownDomain--
		}
		_, _ = fmt.Fprintf(w, "%v %v %v %v\n", sortingSlice[i].DecoyIP, sortingSlice[i].DecoyFailureRate, sortingSlice[i].SampleSize, domain)
	}
	_ = w.Flush()


	sort.Slice(sortingSlice, func(i, j int) bool {
		return sortingSlice[i].SampleSize > sortingSlice[j].SampleSize
	})

	unknownInTop100Count := 0
	goodDecoyCount := 0
	for i:= 0; goodDecoyCount < 100; i++ {
		if sortingSlice[i].DecoyFailureRate < averageFailureRate {
			goodDecoyCount++
		}
		if _, found := al.ipToHostname[sortingSlice[i].DecoyIP]; !found {
			unknownInTop100Count++
		}
	}

	fmt.Printf("%v, #unique decoys: %v, percentage of decoys not in latest decoylist: %v, percentage of good decoy in top 100 decoys by popularity not in latest decoylist: %v\n", filename, len(sortingSlice), float64(numberOfUnknownDomain) / float64(len(sortingSlice)), float64(unknownInTop100Count)/float64(100))
}































