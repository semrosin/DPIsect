package main

import (
	"testing"
	"time"
)

func TestB01_InspectFlowDistinguishesHelloRepeatFromFIN(t *testing.T) {
	now := time.Unix(100, 0)
	hello := []byte{22, 3, 1, 0, 1, 1}
	base := []frame{
		{seq: 100, syn: true},
		{incoming: true, seq: 200, ack: 101, syn: true, ackFlag: true},
		{seq: 101, ack: 201, ackFlag: true},
		{time: now, seq: 101, payload: hello},
	}
	for _, tc := range []struct {
		name     string
		tail     []frame
		repeats  int
		incoming int
	}{
		{"hello retry", []frame{{time: now.Add(281 * time.Millisecond), seq: 101, payload: hello}}, 1, 0},
		{"FIN retry", []frame{{seq: 107, fin: true}, {seq: 107, fin: true}}, 0, 0},
		{"incoming ACK", []frame{{incoming: true, ack: 107, ackFlag: true}}, 0, 1},
		{"other data", []frame{{seq: 107, payload: hello}}, 0, 0},
		{"FIN repeat", []frame{{seq: 107, fin: true}, {seq: 107, fin: true}}, 0, 0},
	} {
		t.Run("B01_"+tc.name, func(t *testing.T) {
			frames := append(append([]frame(nil), base...), tc.tail...)
			result, err := inspectFlow(flow{port: 1234, frames: frames}, hello)
			if err != nil {
				t.Fatal(err)
			}
			if !result.PlanMatches || !result.TCPHandshakeObserved || result.IdenticalHelloRepeats != tc.repeats || result.IncomingAfterHello != tc.incoming {
				t.Fatalf("unexpected review: %+v", result)
			}
			if tc.repeats > 0 && result.FirstHelloRepeatDelayMS != 281 {
				t.Fatalf("repeat delay: %v", result.FirstHelloRepeatDelayMS)
			}
		})
	}
}

func TestB01_InspectFlowRejectsUnverifiableHello(t *testing.T) {
	for _, frames := range [][]frame{
		nil,
		{{syn: true}},
		{{syn: true}, {payload: []byte{1}}},
	} {
		if _, err := inspectFlow(flow{frames: frames}, []byte{1, 2}); err == nil {
			t.Fatal("expected incomplete or mismatched hello to fail review")
		}
	}
}
