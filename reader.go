package main

import (
	"io/ioutil"
	"sort"
	log "github.com/Sirupsen/logrus"
	"fmt"
	"io"
	"os"
)

type StreamReader struct {
	io.Reader
	filenames []string

	currentFile      []byte
	currentSize      uint64
	currentFileIndex int
	currentPtr       uint64

	Position  uint64
	TotalSize uint64
}

type OutOfFiles struct {
	error
	message string
}

func (r *StreamReader) Read(p []byte) (n uint64, err error) {
	if r.currentFile == nil || r.currentPtr == r.currentSize {
		err:=r.openNextFile()
		if err != nil{
			return 0, err
		}

	}

	//copy bytes until we're done
	bytesRead := uint64(0)
	bufflen := uint64(len(p))
	toRead := bufflen
	for {
		diff:=r.currentSize - r.currentPtr
		if toRead > diff {
			//will read past this file, copy all and load the next file
			log.Debugf("Reading from file")
			log.Debugf("r.currentFile[%v:%v]", r.currentPtr,r.currentSize)
			amtRead := uint64(r.currentSize - r.currentPtr)
			copy(r.currentFile, p[bytesRead:])
			bytesRead += amtRead
			toRead -= amtRead
			err := r.openNextFile()

			if err != nil {
				if _, ok := err.(*OutOfFiles); ok {
					return bytesRead, io.EOF
				} else {
					return bytesRead, err
				}
			}
		} else {
			//the current file is enough, read in what is needed and move the pointer
			log.Debugf("Reading from file")
			log.Debugf("r.currentFile[%v:%v]", r.currentPtr,(r.currentSize - toRead))
			copy(r.currentFile[r.currentPtr:(r.currentSize - toRead)], p[bytesRead:])
			r.currentPtr += toRead
			break
		}
	}
	r.Position += bytesRead
	return bytesRead, nil
}

func (r *StreamReader) Skip(amount uint64) (uint64, error) {
	bytesRead := uint64(0)
	toRead := amount
	for {
		size := toRead - (r.currentSize - r.currentPtr)
		if size < 0 {
			amtRead := uint64(r.currentSize - r.currentPtr)
			toRead -= amtRead
			err := r.openNextFile()
			if err != nil {
				if _, ok := err.(*OutOfFiles); ok {
					return bytesRead, io.EOF
				} else {
					return bytesRead, err
				}
			}
		} else {
			bytesRead = amount
			r.currentPtr += toRead
			break
		}
	}
	r.Position += bytesRead
	return amount, nil
}

func (r *StreamReader) openNextFile() error {
	if r.currentFileIndex >= len(r.filenames) {
		return OutOfFiles{message:"OUT"}
	}

	file, err := os.Open(r.filenames[r.currentFileIndex])
	if err != nil {
		return err
	}

	stat, err := file.Stat()
	if err != nil {
		return err
	}

	r.currentSize = uint64(stat.Size())
	r.currentPtr = uint64(0)
	r.currentFile = make([]byte, stat.Size())
	_, err = file.Read(r.currentFile)
	if err != nil {
		return err
	}

	r.currentFileIndex++
	return nil
}

func (r *StreamReader) fetchNextFile() ([]byte, error) {
	//pop off the top of the filename array
	next := r.filenames[len(r.filenames) - 1]
	r.filenames = r.filenames[:len(r.filenames) - 1]
	content, err := ioutil.ReadFile(next)
	if err != nil {
		log.Errorf("Could not open file %v", next)
	}
	return content, err
}

func NewStreamReader(streamId string) (*StreamReader, error) {
	reader := &StreamReader{}

	//find all files in the stream
	dir := fmt.Sprintf("%s/%s/%s", storage_dir, inflight_dir, streamId)
	log.Debugf("Opening all files in %s",dir)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Errorf("Could not process stream %v", streamId)
		return nil, err
	}

	//order the files by name to reconstruct stream in correct order
	reader.filenames = make([]string, len(files))
	for i, f := range files {
		reader.filenames[i] = fmt.Sprintf("%s/%s",dir,f.Name())
		reader.TotalSize += uint64(f.Size())
	}
	sort.Strings(reader.filenames)

	return reader, nil
}
