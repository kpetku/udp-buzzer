package main

import "fmt"
import "strings"
import "strconv"
import "os"
import "bufio"
import "time"
import "encoding/hex"
import "os/user"
import "io/ioutil"

const udpOutThreshold int = 1000
const udpInThreshold int = 1000
const resultsFile string = "/tmp/checker"

var udpCounter datagram

type datagram struct {
	counter
	flood bool
}
type counter struct {
	out int
	in  int
}

func doEvery(d time.Duration, f func(time.Time)) {
	for x := range time.Tick(d) {
		f(x)
	}
}
func hexToIp(ip string) string {
	a, _ := hex.DecodeString(ip)
	return fmt.Sprintf("%v.%v.%v.%v", a[3], a[2], a[1], a[0])
}
func main() {
	if len(os.Args) > 1 {
		if os.Args[1] == "check" {
			if _, err := os.Stat(resultsFile); os.IsNotExist(err) {
				fmt.Println("No event was detected")
				os.Exit(0)
			}
			if _, err := os.Stat(resultsFile); err == nil {
				dat, _ := ioutil.ReadFile(resultsFile)
				// exit as critical
				fmt.Println(string(dat))
				os.Exit(2)
			}
		}
	} else {
		// Go doesn't have a os/poll in stdlib yet https://github.com/golang/go/issues/6222
		doEvery(1000*time.Millisecond, pollProcSnmp)
	}
}
func pollProcUdp() {
	f, _ := os.Open("/proc/net/udp")
	defer closeFile(f)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parseUdp(scanner.Text())
	}
}

func pollProcSnmp(t time.Time) {
	f, _ := os.Open("/proc/net/snmp")
	defer closeFile(f)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parseIt(scanner.Text())
	}
}

func parseUdp(message string) {
	//fmt.Println(message)
	words := strings.Fields(message)
	// Ommit the header
	if message == "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops             " {
		return
	}
	//   968: 7501A8C0:C544 0164A8C0:0035 01 00030F00:00000000 00:00000000 00000000  1000        0 2928361 2 0000000000000000 0
	remoteHexIp := strings.Split(words[2], ":")
	if remoteHexIp[0] != "00000000" {
		// Skip loopback
		if (hexToIp(remoteHexIp[0])) != "127.0.0.1" {
			usr, _ := user.LookupId(words[7])
			d1 := []byte("Outbound UDP target found: " + hexToIp(remoteHexIp[0]) + " uid: " + usr.Username)
			ioutil.WriteFile(resultsFile, d1, 0644)
		}
	}
}

// http://stackoverflow.com/questions/23753306/meaning-of-fields-in-proc-net-udp
func parseIt(message string) {
	words := strings.Fields(message)
	// Ommit the header
	if strings.HasPrefix(message, "Udp: InDatagrams") {
		return
	}
	// Udp: 232120 3324 0 234120 0 0 0 1382
	if strings.HasPrefix(words[0], "Udp:") {
		inTally, _ := strconv.Atoi(words[1])
		outTally, _ := strconv.Atoi(words[4])
		if outTally > udpCounter.out && udpCounter.out != 0 {
			s := outTally - udpCounter.out
			//change := fmt.Sprintf("%d", s)
			if s < udpOutThreshold && udpCounter.flood {
				// fmt.Println("Outbound UDP flood event has ended.")
				udpCounter.setFlood(false)
				os.Remove(resultsFile)
				return
			}
			if s > udpOutThreshold && !udpCounter.flood {
				// fmt.Println("Outbound UDP flood event detected.  Overall outbound UDP rate increased by: " + change)
				// s := fmt.Sprintf("%d", udpCounter.out)
				// s3 := fmt.Sprintf("%d", outTally)
				// fmt.Println("Was/Counted OutDatagrams: " + fmt.Sprintf("%d", udpCounter.out))
				// fmt.Println("Now/Parsed OutDatagrams: " + fmt.Sprintf("%d", outTally))
				udpCounter.setFlood(true)
				pollProcUdp()
				return
			}
		}
		if inTally > udpCounter.in && udpCounter.in != 0 {
			s := inTally - udpCounter.in
			//change := fmt.Sprintf("%d", s)
			if s > udpInThreshold {
				//   fmt.Println("Inbound UDP rate increased by: " + change)
			}
		}
		udpCounter.setIn(inTally)
		udpCounter.setOut(outTally)
	}
}
func (counter *datagram) setIn(input int) *datagram {
	counter.in = input
	return counter
}
func (counter *datagram) setOut(input int) *datagram {
	counter.out = input
	return counter
}
func (counter *datagram) setFlood(input bool) *datagram {
	counter.flood = input
	return counter
}
func closeFile(f *os.File) {
	f.Close()
}
