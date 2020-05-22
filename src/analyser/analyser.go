package analyser

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"os/exec"
	"sort"
	"strings"
)


type StatsForSpecificDecoy struct {
	numSuccesses int
	numFailures int
	failureRate float64
}

type AggregatedCountryStats struct {
	decoyStatsForThisCountry map[string]*StatsForSpecificDecoy // decoy ip -> stats
}

type Analyser struct {
	countryStats map[string]*AggregatedCountryStats // Country name -> stats
	decoyStats map[string]*StatsForSpecificDecoy // Decoy ip -> stats
	ipToHostname map[string]string
}


func InitAnalyser() *Analyser{
	al := new(Analyser)
	al.countryStats = make(map[string]*AggregatedCountryStats)
	al.decoyStats = make(map[string]*StatsForSpecificDecoy)
	al.ipToHostname = make(map[string]string)
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




func (al *Analyser) ReadDecoyList() {
	err, stdout, stderr := Shellout("git pull")
	err, stdout, stderr = Shellout("ls")
	files := strings.Split(stdout, "\n")
	sampleName := "-decoys.txt"
	fileNameOfLatestDecoyList := ""

	for _, item := range files {
		if CheckEnd(item, sampleName) {
			fileNameOfLatestDecoyList = item
		}
	}

	err, stdout, stderr = Shellout("ls")
	fmt.Println(err, stdout, stderr)
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

func (al *Analyser) ReadNetFlow() {
	f, err := os.Open("netflow.csv")
	defer f.Close()
	if err != nil {
		log.Fatal(err)
	}

	csvr := csv.NewReader(f)
	_, err = csvr.Read()
	if err != nil {
		log.Fatal(err)
	}

	for {
		row, err := csvr.Read()
		if err != nil {
			if err == io.EOF {
				return
			} else {
				log.Fatal(err)
			}
		}
		if len(row) == 0 {
			continue
		}
		detectorAddr := row[57]
		clientCountry := row[44]

		//country stuff
		if _, exist := al.countryStats[clientCountry]; !exist {
			al.countryStats[clientCountry] = new(AggregatedCountryStats)
			al.countryStats[clientCountry].decoyStatsForThisCountry = make(map[string]*StatsForSpecificDecoy)
		}
		if _, exist := al.countryStats[clientCountry].decoyStatsForThisCountry[detectorAddr]; !exist {
			al.countryStats[clientCountry].decoyStatsForThisCountry[detectorAddr] = new(StatsForSpecificDecoy)
		}
		al.countryStats[clientCountry].decoyStatsForThisCountry[detectorAddr].numSuccesses++

		//decoy stuff
		if _, exist := al.decoyStats[detectorAddr]; !exist {
			al.decoyStats[detectorAddr] = new(StatsForSpecificDecoy)
		}
		al.decoyStats[detectorAddr].numSuccesses++
	}
}


func (al *Analyser) ReadFailedDecoy() {
	f, err := os.Open("faileddecoy.csv")
	defer f.Close()
	if err != nil {
		log.Fatal(err)
	}

	csvr := csv.NewReader(f)
	_, err = csvr.Read()
	if err != nil {
		log.Fatal(err)
	}

	for {
		row, err := csvr.Read()
		if err != nil {
			if err == io.EOF {
				return
			} else {
				log.Fatal(err)
			}
		}
		if len(row) == 0 {
			continue
		}
		detectorAddr := row[58]
		clientCountry := row[44]

		//country stuff
		if _, exist := al.countryStats[clientCountry]; !exist {
			al.countryStats[clientCountry] = new(AggregatedCountryStats)
			al.countryStats[clientCountry].decoyStatsForThisCountry = make(map[string]*StatsForSpecificDecoy)
		}
		if _, exist := al.countryStats[clientCountry].decoyStatsForThisCountry[detectorAddr]; !exist {
			al.countryStats[clientCountry].decoyStatsForThisCountry[detectorAddr] = new(StatsForSpecificDecoy)
		}
		al.countryStats[clientCountry].decoyStatsForThisCountry[detectorAddr].numFailures++

		//decoy stuff
		if _, exist := al.decoyStats[detectorAddr]; !exist {
			al.decoyStats[detectorAddr] = new(StatsForSpecificDecoy)
		}
		al.decoyStats[detectorAddr].numFailures++
	}
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


