package main

import (
	"analyser"
)

func main() {
	var al *analyser.Analyser
	al = analyser.InitAnalyser()
	al.ReadDecoyList()
	al.FetchLog()
	al.ReadLog()

	terminationChannel1 := make(chan bool)
	terminationChannel2 := make(chan bool)
	go al.ProcessCountryChannel(terminationChannel2)
	go al.ProcessDecoyChannel(terminationChannel1)
	for _ = range terminationChannel1 {}
	for _ = range terminationChannel2 {}

	terminationChannel3 := make(chan bool)
	terminationChannel4 := make(chan bool)
	go al.ComputeFailureRateForCountry(terminationChannel3)
	go al.ComputeFailureRateForDecoy(terminationChannel4)
	for _ = range terminationChannel3 {}
	for _ = range terminationChannel4 {}

	al.PrintDecoyReports(10, 100)
	al.PrintDecoyReportFor("IR", 10, 100)
}
