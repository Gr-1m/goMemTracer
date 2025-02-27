package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	wincall "golang.org/x/sys/windows"
)

var peHeader = []byte{
	0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
	0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
	0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
	0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
	0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
	0x6D, 0x6F, 0x64, 0x65,
}

var (
	modpsapi                 = wincall.NewLazyDLL("psapi.dll")
	procEnumProcessModules   = modpsapi.NewProc("EnumProcessModules")
	procGetModuleFileNameExW = modpsapi.NewProc("GetModuleFileNameExW")
)

type ProcessModuleInfo struct {
	ProcessName string `json:"Process Name"`
	PID         uint32 `json:"PID"`
	ProcessPath string `json:"Process Path"`
	ModulePath  string `json:"Module Path"`
	ModuleName  string `json:"Module Name"`
}

type ReflectiveDLLInfo struct {
	PID         uint32 `json:"PID"`
	ProcessName string `json:"Process Name"`
	ProcessPath string `json:"Process Path"`
	Reflective  bool   `json:"Reflective DLL load"`
	BaseAddress uint64 `json:"Base Address"`
	Size        uint64 `json:"Size"`
}

type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

func main() {
	var moduleName string
	var reflectiveScan bool
	flag.StringVar(&moduleName, "m", "", "Looking for specific loaded DLL")
	flag.BoolVar(&reflectiveScan, "r", false, "Looking for reflective DLL loading")
	flag.Parse()

	var moduleResults []ProcessModuleInfo
	var reflectiveResults []ReflectiveDLLInfo

	if moduleName != "" {
		fmt.Printf("Scanning for module %s...\n", moduleName)
		moduleResults, _ = scanModules(moduleName)
	}

	if reflectiveScan {
		fmt.Println("Scanning for reflective DLL loading...")
		reflectiveResults, _ = scanReflective()
	}

	if !reflectiveScan && moduleName == "" {
		fmt.Println("No arguments provided")
		return
	}

	printResults(moduleResults, reflectiveResults, moduleName)
}

func scanModules(moduleName string) ([]ProcessModuleInfo, error) {
	pids, err := enumProcesses()
	if err != nil {
		return nil, err
	}

	var results []ProcessModuleInfo
	for _, pid := range pids {
		if pid == 0 {
			continue
		}

		hProc, err := wincall.OpenProcess(wincall.PROCESS_QUERY_INFORMATION|wincall.PROCESS_VM_READ, false, pid)
		if err != nil {
			continue
		}
		defer wincall.CloseHandle(hProc)

		procPath, _ := getProcessPath(pid)
		procName := filepath.Base(procPath)

		modules, _ := enumProcessModules(hProc)
		for _, hMod := range modules {
			modPath, _ := getModuleFileName(hProc, hMod)
			modName := filepath.Base(modPath)
			if modName == moduleName {
				results = append(results, ProcessModuleInfo{
					ProcessName: procName,
					PID:         pid,
					ProcessPath: filepath.Dir(procPath),
					ModulePath:  filepath.Dir(modPath),
					ModuleName:  modName,
				})
			}
		}
	}
	return results, nil
}

func scanReflective() ([]ReflectiveDLLInfo, error) {
	si := getSystemInfo()
	minAddr := si.lpMinimumApplicationAddress
	maxAddr := si.lpMaximumApplicationAddress

	pids, _ := enumProcesses()
	var results []ReflectiveDLLInfo

	for _, pid := range pids {
		if pid == 0 {
			continue
		}

		hProc, err := wincall.OpenProcess(wincall.PROCESS_QUERY_INFORMATION|wincall.PROCESS_VM_READ, false, pid)
		if err != nil {
			continue
		}
		defer wincall.CloseHandle(hProc)

		procPath, _ := getProcessPath(pid)
		procName := filepath.Base(procPath)

		var baseAddr uintptr = minAddr
		for baseAddr < maxAddr {
			var mbi memoryBasicInformation
			ret, _, _ := wincall.Syscall6(wincall.NewLazyDLL("kernel32.dll").NewProc("VirtualQueryEx").Addr(),
				4,
				uintptr(hProc),
				baseAddr,
				uintptr(unsafe.Pointer(&mbi)),
				unsafe.Sizeof(mbi),
				0, 0)

			if ret == 0 {
				break
			}

			if mbi.State == 0x1000 && mbi.Type == 0x40000 &&
				(mbi.Protect == 0x40 || mbi.Protect == 0x20 || mbi.Protect == 0x04) {

				buffer := make([]byte, mbi.RegionSize)
				var bytesRead uint32
				err := wincall.ReadProcessMemory(hProc, baseAddr, &buffer[0], uintptr(len(buffer)), &bytesRead)
				if err != nil || bytesRead < 116 {
					baseAddr += mbi.RegionSize
					continue
				}

				if bytes.Equal(buffer[:116], peHeader) {
					filename := fmt.Sprintf("%x.exe", baseAddr)
					os.WriteFile(filename, buffer, 0644)

					results = append(results, ReflectiveDLLInfo{
						PID:         pid,
						ProcessName: procName,
						ProcessPath: filepath.Dir(procPath),
						Reflective:  true,
						BaseAddress: uint64(baseAddr),
						Size:        uint64(mbi.RegionSize),
					})
				}
			}
			baseAddr += mbi.RegionSize
		}
	}
	return results, nil
}

func enumProcesses() ([]uint32, error) {
	snapshot, err := wincall.CreateToolhelp32Snapshot(wincall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer wincall.CloseHandle(snapshot)

	var entry wincall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	err = wincall.Process32First(snapshot, &entry)
	if err != nil {
		return nil, err
	}

	var pids []uint32
	for {
		pids = append(pids, entry.ProcessID)
		err = wincall.Process32Next(snapshot, &entry)
		if err != nil {
			if err == wincall.ERROR_NO_MORE_FILES {
				break
			}
			return nil, err
		}
	}
	return pids, nil
}

func getProcessPath(pid uint32) (string, error) {
	h, err := wincall.OpenProcess(wincall.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return "", err
	}
	defer wincall.CloseHandle(h)

	var buf [wincall.MAX_PATH]uint16
	_, err = wincall.GetModuleFileNameEx(h, 0, &buf[0], wincall.MAX_PATH)
	return wincall.UTF16ToString(buf[:]), err
}

func enumProcessModules(hProc wincall.Handle) ([]wincall.Handle, error) {
	var needed uint32
	err := enumProcessModulesCall(hProc, nil, 0, &needed)
	if err != nil {
		return nil, err
	}

	count := needed / uint32(unsafe.Sizeof(wincall.Handle(0)))
	modules := make([]wincall.Handle, count)
	err = enumProcessModulesCall(hProc, &modules[0], needed, &needed)
	return modules, err
}

func enumProcessModulesCall(hProc wincall.Handle, modules *wincall.Handle, cb uint32, needed *uint32) error {
	r1, _, e1 := syscall.Syscall6(procEnumProcessModules.Addr(), 4,
		uintptr(hProc),
		uintptr(unsafe.Pointer(modules)),
		uintptr(cb),
		uintptr(unsafe.Pointer(needed)),
		0, 0)
	if r1 == 0 {
		return e1
	}
	return nil
}

func getModuleFileName(hProc wincall.Handle, hMod wincall.Handle) (string, error) {
	var buf [wincall.MAX_PATH]uint16
	r1, _, e1 := syscall.Syscall6(procGetModuleFileNameExW.Addr(), 4,
		uintptr(hProc),
		uintptr(hMod),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(wincall.MAX_PATH),
		0, 0)
	if r1 == 0 {
		return "", e1
	}
	return wincall.UTF16ToString(buf[:]), nil
}

type systemInfo struct {
	wProcessorArchitecture      uint16
	wReserved                   uint16
	dwPageSize                  uint32
	lpMinimumApplicationAddress uintptr
	lpMaximumApplicationAddress uintptr
	dwActiveProcessorMask       uintptr
	dwNumberOfProcessors        uint32
	dwProcessorType             uint32
	dwAllocationGranularity     uint32
	wProcessorLevel             uint16
	wProcessorRevision          uint16
}

func getSystemInfo() *systemInfo {
	var si systemInfo
	wincall.Syscall(wincall.NewLazyDLL("kernel32.dll").NewProc("GetSystemInfo").Addr(),
		1, uintptr(unsafe.Pointer(&si)), 0, 0, 0)
	return &si
}

func printResults(moduleResults []ProcessModuleInfo, reflectiveResults []ReflectiveDLLInfo, moduleName string) {
	if len(moduleResults) > 0 {
		file, _ := os.Create("ModuleScan.json")
		defer file.Close()
		encoder := json.NewEncoder(file)
		for _, res := range moduleResults {
			encoder.Encode(res)
		}
		fmt.Printf("Created ModuleScan.json for %s\n", moduleName)
	}

	if len(reflectiveResults) > 0 {
		file, _ := os.Create("DLLlst.json")
		defer file.Close()
		encoder := json.NewEncoder(file)
		for _, res := range reflectiveResults {
			encoder.Encode(res)
		}
		fmt.Println("Created DLLlst.json")
	}
}
