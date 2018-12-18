package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	log "github.com/cohix/simplog"
	"github.com/pkg/errors"
	"github.com/taask/runner-golang"
)

type addition struct {
	First  int
	Second int
}

type answer struct {
	Answer int
}

var serverHost = flag.String("host", "taask-server", "host for taask-server")
var serverPort = flag.String("port", "3687", "port for taask-server")

func main() {
	flag.Parse()

	runner, err := taask.NewRunner("io.taask.k8s", []string{}, func(task []byte) (interface{}, error) {
		var problem addition
		if err := json.Unmarshal(task, &problem); err != nil {
			return nil, errors.Wrap(err, "failed to Unmarshal")
		}

		seconds := rand.Intn(5)

		log.LogInfo(fmt.Sprintf("solving %d + %d in %d seconds", problem.First, problem.Second, seconds))

		<-time.After(time.Second * time.Duration(seconds))

		return answer{Answer: problem.First + problem.Second}, nil
	})

	if err != nil {
		log.LogError(errors.Wrap(err, "failed to NewRunner"))
		os.Exit(1)
	}

	joinCode, ok := os.LookupEnv("TAASK_JOIN_CODE")
	if !ok {
		if len(os.Args) != 2 {
			log.LogError(errors.New("missing argument: join code"))
			os.Exit(1)
		}

		joinCode = os.Args[1]
	}

	if err := runner.ConnectAndRun(joinCode, *serverHost, *serverPort); err != nil {
		log.LogError(errors.Wrap(err, "failed to ConnectAndRun"))
		os.Exit(1)
	}
}
