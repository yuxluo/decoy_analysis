package main

import (
	"analyser"
)

func main() {
	al := analyser.InitAnalyser()
	//al.ReadDecoyList()
	//al.FetchLog()
	al.ReadLog()
	al.ReadNetFlow()
	al.ReadFailedDecoy()
	//al.ComputeFailureRateForCountry()
	//al.ComputeFailureRateForDecoy()
	//al.PrintDecoyReports(10, 10)
	//al.PrintDecoyReportFor("Turkmenistan", 10, 10)
}
