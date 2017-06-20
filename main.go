package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/groob/plist"
	osquery "github.com/kolide/osquery-go"
)

var version = "dev"

func main() {
	var (
		flQueries    = flag.String("queries", "", "path to line delimited query file")
		flSocketPath = flag.String("socket", "/var/osquery/osquery.em", "path to osqueryd socket")
	)
	flag.Parse()

	if *flQueries == "" {
		fmt.Println("No query file specified.")
		flag.Usage()
		os.Exit(1)
	}
	var conditions MunkiConditions
	if err := conditions.Load(); err != nil {
		if os.IsNotExist(err) {
			conditions = make(MunkiConditions)
		} else {
			log.Fatal(err)
		}
	}

	client, err := osquery.NewClient(*flSocketPath, 10*time.Second)
	if err != nil {
		fmt.Println("Error creating Thrift client: " + err.Error())
		os.Exit(1)
	}
	defer client.Close()

	queries := readQueries(*flQueries)
	wclient := &OsqueryClient{client}
	resp, err := wclient.RunQueries(queries...)
	if err != nil {
		log.Fatal(err)
	}
	for r := range resp {
		for k, v := range r {
			fmt.Println(k, v)
			conditions[fmt.Sprintf("osquery_%s", k)] = []string{v}
		}
	}

	if err := conditions.Save(); err != nil {
		log.Fatal(err)
	}
}

func readQueries(path string) []string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	lr := bufio.NewReader(bytes.NewReader(data))
	var lines []string
	for {
		line, _, err := lr.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		lines = append(lines, string(line))
	}
	return lines
}

type OsqueryClient struct {
	*osquery.ExtensionManagerClient
}

func (c *OsqueryClient) RunQueries(queries ...string) (<-chan map[string]string, error) {
	responses := make(chan map[string]string)
	go func() {
		for _, q := range queries {
			resp, err := c.Query(q)
			if err != nil {
				log.Println(err)
				return
			}
			if resp.Status.Code != 0 {
				log.Printf("got status %d\n", resp.Status.Code)
				return
			}
			for _, r := range resp.Response {
				responses <- r
			}
		}
		close(responses)
	}()
	return responses, nil
}

type MunkiConditions map[string][]string

func (c *MunkiConditions) Load() error {
	f, err := os.Open("/Library/Managed Installs/ConditionalItems.plist")
	if err != nil {
		return err
	}

	if err := plist.NewDecoder(f).Decode(c); err != nil {
		return err
	}
	return f.Close()
}

func (c *MunkiConditions) Save() error {
	f, err := os.OpenFile("/Library/Managed Installs/ConditionalItems.plist", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	enc := plist.NewEncoder(f)
	enc.Indent("  ")
	if err := enc.Encode(c); err != nil {
		return err
	}
	return f.Close()
}

func getSocket() string {
	if len(os.Args) < 2 {
		fmt.Printf(`Usage: %s SOCKET_PATH QUERY\n

Requests osqueryd to run the provided query and prints the results.
`, os.Args[0])
		os.Exit(1)
	}
	return os.Args[1]
}
