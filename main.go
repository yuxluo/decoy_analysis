package main

import (
	"analyser"
)

func main() {
	al := analyser.InitAnalyser()
	//al.ReadDecoyList()
	//al.FetchLog()
	al.ReadLog()

	terminationChannel1 := make(chan bool)
	terminationChannel2 := make(chan bool)
	go al.ProcessCountryChannel(terminationChannel2)
	go al.ProcessDecoyChannel(terminationChannel1)
	for _ = range terminationChannel1 {
		continue
	}
	for _ = range terminationChannel2 {
		continue
	}

	go al.ComputeFailureRateForCountry()
	go al.ComputeFailureRateForDecoy()
	al.PrintDecoyReports(10, 10)
	al.PrintDecoyReportFor("IR", 10, 10)
}
