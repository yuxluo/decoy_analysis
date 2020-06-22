package main

import (
	"github.com/yuxluo/decoy_analysis/analyser"
	"fmt"
	"time"
)
const IntervalPeriod time.Duration = 24 * time.Hour

const HourToTick int = 00
const MinuteToTick int = 05
const SecondToTick int = 00

type jobTicker struct {
	timer *time.Timer
}

func runningRoutine() {
	jobTicker := &jobTicker{}
	jobTicker.updateTimer()
	for {
		<-jobTicker.timer.C
		fmt.Println(time.Now(), "- just ticked")
		RunAnalysis("a")
		jobTicker.updateTimer()
	}
}

func (t *jobTicker) updateTimer() {
	nextTick := time.Date(time.Now().Year(), time.Now().Month(),
		time.Now().Day(), HourToTick, MinuteToTick, SecondToTick, 0, time.Local)
	if !nextTick.After(time.Now()) {
		nextTick = nextTick.Add(IntervalPeriod)
	}
	fmt.Println(nextTick, "- next tick")
	diff := nextTick.Sub(time.Now())
	if t.timer == nil {
		t.timer = time.NewTimer(diff)
	} else {
		t.timer.Reset(diff)
	}
}

func main() {
	for i := -1; i >= -7; i-- {
		date := time.Now().AddDate(0, 0, i).Format("2006-01-02")
		RunAnalysis(date)
	}
}

func RunAnalysis(date string) {
	var al *analyser.Analyser
	al = analyser.InitAnalyser()
	al.ReadDecoyList()
	al.FetchLog(date)
	al.ReadLog(date)

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

	al.PrintFailureRate(date)
}
