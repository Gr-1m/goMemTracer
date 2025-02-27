package main

import (
	"flag"
	"fmt"
	wincall "golang.org/x/sys/windows"
)

var (
	scanDllRef bool
	scanModule string
)

func init() {

	flag.BoolVar(&scanDllRef, "r", false, "")
	flag.StringVar(&scanModule, "m", "", "Looking for spcefic loaded DLL")

	flag.Parse()
}

func EnumProcs() (pids []uint32, size uint32, err error) {

	pids = make([]uint32, 1024)

	err = wincall.EnumProcesses(pids, &size)
	if err != nil {
		fmt.Println(err)
		return
	}
	size /= 4
	pids = pids[:size]

	return
}
func ReflectiveScan() (dLst []uint32) {
	return
}

func ModuleScan() (mLst []uint32) {
	pids, _, err := EnumProcs()
	if err != nil {

	}
	for _, pid := range pids {
		if pid == 0 {
			continue
		}
		hProc, err := wincall.OpenProcess(wincall.PROCESS_QUERY_INFORMATION|wincall.PROCESS_VM_READ, false, pid)
		if err != nil {
		}
		wincall.GetModuleHandleEx()

	}

	return
}

func printproc(Mlst, Dlst []uint32, mName string) {
	if len(Mlst) != 0 {

	}

	if len(Dlst) != 0 {

	}

	fmt.Println("Done...")
}

func main() {
	_, _, err := EnumProcs()
	if err != nil {
		fmt.Println("EnumProcs error:", err)
	}

	if scanModule != "" {
		fmt.Println("Scan for Module", scanModule, "......")
		//
		fmt.Println("Done...")

	}
	if scanDllRef {
		fmt.Println("Scan for Reflictive DLL loading ......")
		//
		fmt.Println("Done...")
	}

	printproc()
}
