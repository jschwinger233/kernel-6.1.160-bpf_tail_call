package main

import (
	"errors"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/jschwinger233/kernel-6.1.160-bpf_tail_call/bpf"
)

func main() {
	objs := bpf.BpfObjects{}

	start := time.Now()
	collectionSpec, err := bpf.LoadBpf()
	if err != nil {
		log.Fatalf("failed to load BPF spec: %v", err)
	}
	if err := collectionSpec.LoadAndAssign(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("verifier error: %v\n%s", ve, ve.Log)
		}
		log.Fatalf("failed to load and assign BPF objects: %v", err)
	}
	log.Printf("BPF objects loaded successfully in %s", time.Since(start))

}
