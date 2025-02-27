package main

import (
	"flag"
	"fmt"
	wincall "golangOrg/x/sys/windows"
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

func ModuleScan(moduleName string) (mLst []uint32) {
	pids, _, err := EnumProcs()
	if err != nil {

	}
	for _, pid := range pids {
		if pid == 0 {
			continue
		}
		hProc, e1 := wincall.OpenProcess(wincall.PROCESS_QUERY_INFORMATION|wincall.PROCESS_VM_READ, false, pid)
		if e1 != nil {
			fmt.Println("[-] OpenProcess Error:", e1, "pid:", pid)
			continue
		}
		//wincall.GetModuleHandleEx(hProc)
		var ProcName uint16
		var mod0 = new(wincall.Handle)
		e1 = wincall.GetModuleFileNameEx(hProc, *mod0, &ProcName, 0)
		if e1 != nil {
			fmt.Println("[-] GetModuleFileNameEx Error:", e1, "pid:", pid)
			continue
		}

		var mods = make([]wincall.Handle, 32)
		e1 = wincall.EnumProcessModules(hProc, &mods[0], 32, nil)
		if e1 != nil {
			fmt.Println("[-] EnumProcessModules Error:", e1, "pid:", pid)
			continue
		}
		for _, mod := range mods {
			var modString uint16
			e2 := wincall.GetModuleFileNameEx(hProc, mod, &modString, 0)
			if e2 != nil {
				fmt.Println("[-] GetModuleFileNameEx Error:", e2, "mod:", mod)
				continue
			}
			fmt.Println("[-] ModuleName:", wincall.UTF16PtrToString(&modString), "pid:", pid)
			if wincall.UTF16PtrToString(&modString) == moduleName {

			}
		}

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

	var Mlst []uint32
	if scanModule != "" {
		fmt.Println("Scan for Module", scanModule, "......")
		Mlst = ModuleScan(scanModule)
		fmt.Println("Done...")

	}
	if scanDllRef {
		fmt.Println("Scan for Reflictive DLL loading ......")
		//
		fmt.Println("Done...")
	}

	printproc(Mlst, Mlst, "ReflectiveScan")
}
