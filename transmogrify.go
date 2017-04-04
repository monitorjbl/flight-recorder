package main

import (
	"strings"
	"strconv"
	"fmt"
	"os"
	log "github.com/Sirupsen/logrus"
	"io"
)

func httpStartLine(line *string) HttpEvent {
	if strings.HasSuffix(*line, "HTTP/1.1") {
		matches := clientRequestRegex.FindAllString(*line, -1)
		return ClientRequestEvent{
			Method: matches[1],
			Path:   matches[2],
			Version:matches[3]}
	} else if strings.HasPrefix(*line, "HTTP/1.1") {
		matches := serverResponseRegex.FindAllString(*line, -1)
		return ServerResponseEvent{
			Status: matches[2],
			Version:matches[1]}
	} else {
		return nil
	}
}

func contentLength(line *string) int {
	if strings.HasPrefix(*line, "Content-Length: ") {
		split := strings.Split(*line, ": ")
		l, _ := strconv.Atoi(strings.TrimSpace(split[1]))
		return l
	} else {
		return -1
	}
}

func transmogrify(streamId string) {
	dir := fmt.Sprintf("%s/%s/%s", storage_dir, inflight_dir, streamId)
	defer func() {
		log.Debugf("Removing inflight dir for stream %v", streamId)
		os.RemoveAll(dir)
	}()

	reader, err := NewStreamReader(streamId)
	if err != nil {
		log.Errorf("Could not transmogrify stream %v: %v", streamId, err)
		return
	}

	//Go byte-by-byte through the files content and look for <CR><LF> combinations.
	events := []HttpEvent{}
	var currentEvent HttpEvent = nil
	scanningEvent := false
	buffer := make([]byte, 1024)
	window := [2]byte{}
	start := 0
	for {
		bytesRead, err := reader.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Errorf("Error reading packet data: %v", err)
			return
		}

		for i := uint64(0); i < bytesRead-1; i++ {
			window[0] = buffer[i]
			window[1] = buffer[i + 1]
			if window == crlf {
				line := string(buffer[start:i - 1])
				if hsl := httpStartLine(&line); !scanningEvent && hsl != nil {
					currentEvent = hsl
					scanningEvent = true
				} else if cl := contentLength(&line); scanningEvent && cl >= 0 {
					//if this is a client upload, save the data. else, discard it
					reader.Skip(uint64(cl))
					break
				}
			}
		}
		events = append(events, currentEvent)
	}

}