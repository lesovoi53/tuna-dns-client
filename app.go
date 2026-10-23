package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"tuna-dns-client/internal/profile"
)

type Result struct {
	Resolver string `json:"resolver"`
	Domain   string `json:"domain"`
	Valid    bool   `json:"valid"`
	Upload   int    `json:"upload"`
	Download int    `json:"download"`
}
type ScanState struct {
	Done    int      `json:"done"`
	Total   int      `json:"total"`
	Workers int      `json:"workers"`
	Running bool     `json:"running"`
	Domain  string   `json:"domain"`
	Results []Result `json:"results"`
	Error   string   `json:"error"`
}
type State struct {
	Connection  ConnectionState   `json:"connection"`
	ScanWorkers int               `json:"scanWorkers"`
	Profiles    []profile.Profile `json:"profiles"`
	Selected    int               `json:"selected"`
	Port        int               `json:"port"`
	Status      string            `json:"status"`
	Scan        ScanState         `json:"scan"`
	Logs        []string          `json:"logs"`
}
type ConnectionState struct {
	RetryAt   int64  `json:"retryAt"`
	Stage     string `json:"stage"`
	StartedAt int64  `json:"startedAt"`
	Attempt   int    `json:"attempt"`
	Done      int    `json:"done"`
	Total     int    `json:"total"`
}

// Called under a.mu. Only allow-listed structured markers reach the UI;
// raw native diagnostics may contain credentials and are never forwarded.
func (a *App) runtimeEvent(line string) {
	stages := map[string]string{
		"TUNA_MASTER_CONNECTING":   "Запуск DNS-туннеля",
		"TUNA_STAGE_MTU":           "Проверка резолверов и MTU",
		"TUNA_STAGE_MTU_FAILED":    "Проверка резолверов/MTU не прошла; ожидается повторная попытка",
		"TUNA_STAGE_SESSION":       "Установка сессии с сервером",
		"TUNA_STAGE_SESSION_RETRY": "Сессия не установлена; ожидание повторной попытки",
		"TUNA_STAGE_SESSION_OK":    "Сессия установлена; запуск локального SOCKS5",
		"TUNA_STAGE_RESET":         "Сессия сброшена; восстановление подключения",
		"TUNA_MASTER_READY":        "SOCKS5 готов к работе",
	}
	if stage, ok := stages[line]; ok {
		a.Connection.RetryAt = 0
		a.Connection.Stage = stage
		if line == "TUNA_STAGE_MTU" {
			a.Connection.Done = 0
			a.Connection.Total = 0
		}
		if line == "TUNA_STAGE_SESSION" {
			a.Connection.Attempt++
		}
		if line == "TUNA_MASTER_READY" {
			a.Status = "connected"
		} else {
			a.Status = "connecting"
		}
		a.log(stage)
		return
	}
	if strings.HasPrefix(line, "TUNA_SCAN_PROGRESS ") {
		var done, total int
		if n, e := fmt.Sscanf(line, "TUNA_SCAN_PROGRESS %d %d", &done, &total); e == nil && n == 2 && total > 0 && done >= 0 && done <= total {
			a.Connection.Done = done
			a.Connection.Total = total
			if done == total {
				a.log(fmt.Sprintf("Проверка резолверов/MTU: %d из %d", done, total))
			}
		}
	}
	if strings.HasPrefix(line, "TUNA_MASTER_ERROR ") {
		a.Connection.Stage = "Ядро сообщило об ошибке"
		a.log(a.Connection.Stage)
	}
	if strings.HasPrefix(line, "TUNA_SESSION_RETRY ") {
		var seconds int
		if n, e := fmt.Sscanf(line, "TUNA_SESSION_RETRY %d", &seconds); e == nil && n == 1 && seconds >= 0 && seconds <= 86400 {
			a.Connection.RetryAt = time.Now().Add(time.Duration(seconds) * time.Second).UnixMilli()
			a.log(fmt.Sprintf("Следующая попытка через %d с", seconds))
		}
	}
}

type saved struct {
	ScanWorkers int               `json:"scanWorkers"`
	Profiles    []profile.Profile `json:"profiles"`
	Selected    int               `json:"selected"`
	Port        int               `json:"port"`
}
type App struct {
	mu sync.Mutex
	State
	dir, core  string
	cancel     context.CancelFunc
	done       chan struct{}
	scanCancel context.CancelFunc
	scanDone   chan struct{}
	root       context.Context
}

func newApp(ctx context.Context, dir, core string) (*App, error) {
	if err := privateDir(dir); err != nil {
		return nil, err
	}
	a := &App{root: ctx, dir: dir, core: core, State: State{ScanWorkers: 32, Profiles: []profile.Profile{}, Port: 10808, Status: "disconnected", Logs: []string{}, Scan: ScanState{Results: []Result{}}}}
	raw, err := os.ReadFile(filepath.Join(dir, "profiles.dpapi"))
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	raw, err = crypt(raw, false)
	if err != nil {
		return nil, fmt.Errorf("не удалось расшифровать профили текущего пользователя Windows")
	}
	var s saved
	if json.Unmarshal(raw, &s) != nil || s.Port < 1024 || s.Port > 65535 || s.Selected < 0 || (len(s.Profiles) > 0 && s.Selected >= len(s.Profiles)) {
		return nil, fmt.Errorf("повреждён файл профилей")
	}
	for _, p := range s.Profiles {
		if err = p.Validate(); err != nil {
			return nil, fmt.Errorf("некорректный сохранённый профиль")
		}
	}
	a.Profiles = s.Profiles
	if a.Profiles == nil {
		a.Profiles = []profile.Profile{}
	}
	a.Selected = s.Selected
	a.Port = s.Port
	if s.ScanWorkers >= 1 && s.ScanWorkers <= 128 {
		a.ScanWorkers = s.ScanWorkers
	}
	return a, nil
}
func (a *App) persist() error {
	raw, err := json.Marshal(saved{Profiles: a.Profiles, Selected: a.Selected, Port: a.Port, ScanWorkers: a.ScanWorkers})
	if err != nil {
		return err
	}
	raw, err = crypt(raw, true)
	if err != nil {
		return err
	}
	tmp := filepath.Join(a.dir, "profiles.dpapi.tmp")
	if err = os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(a.dir, "profiles.dpapi"))
}
func (a *App) log(s string) {
	a.Logs = append(a.Logs, time.Now().Format("15:04:05")+" · "+s)
	if len(a.Logs) > 200 {
		a.Logs = a.Logs[len(a.Logs)-200:]
	}
}
func (a *App) snapshot() State {
	a.mu.Lock()
	defer a.mu.Unlock()
	raw, _ := json.Marshal(a.State)
	var s State
	json.Unmarshal(raw, &s)
	return s
}
func (a *App) busy() bool { return a.cancel != nil || a.scanCancel != nil }
func (a *App) current() (profile.Profile, error) {
	if len(a.Profiles) == 0 || a.Selected >= len(a.Profiles) {
		return profile.Profile{}, fmt.Errorf("сначала импортируйте профиль")
	}
	return a.Profiles[a.Selected], nil
}
func (a *App) runtimeFiles(p profile.Profile, domains []string, pairs map[string][]string, port int) (string, error) {
	dir, err := os.MkdirTemp(a.dir, "run-")
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(dir)
		}
	}()
	conf, err := profile.TOML(p, port, domains)
	if err != nil {
		return "", err
	}
	all := []string{}
	for _, d := range domains {
		all = append(all, pairs[d]...)
	}
	all, err = profile.NormalizeResolvers(all)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(pairs)
	if err != nil {
		return "", err
	}
	for name, data := range map[string][]byte{"config.toml": []byte(conf), "resolvers.txt": []byte(strings.Join(all, "\n")), "pairs.json": b} {
		if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return "", err
		}
	}
	ok = true
	return dir, nil
}
func (a *App) command(ctx context.Context, dir string, scan bool) *exec.Cmd {
	args := []string{"-config", filepath.Join(dir, "config.toml"), "-resolvers", filepath.Join(dir, "resolvers.txt"), "-pairs", filepath.Join(dir, "pairs.json")}
	if scan {
		args = append(args, "-scan")
	}
	cmd := exec.CommandContext(ctx, a.core, args...)
	cmd.Dir = dir
	hide(cmd)
	return cmd
}
func (a *App) start() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy() {
		return fmt.Errorf("сначала остановите подключение или сканирование")
	}
	p, err := a.current()
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(a.Port)))
	if err != nil {
		return fmt.Errorf("локальный порт занят; измените его в параметрах")
	}
	listener.Close()
	pairs := map[string][]string{}
	for _, d := range p.Domains {
		pairs[d] = p.ResolversFor(d)
	}
	dir, err := a.runtimeFiles(p, p.Domains, pairs, a.Port)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(a.root)
	cmd := a.command(ctx, dir, false)
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		os.RemoveAll(dir)
		return err
	}
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		cancel()
		os.RemoveAll(dir)
		return fmt.Errorf("не удалось запустить ядро")
	}
	job, err := childJob(cmd.Process.Pid)
	if err != nil {
		cancel()
		cmd.Wait()
		os.RemoveAll(dir)
		return err
	}
	a.cancel = cancel
	a.done = make(chan struct{})
	done := a.done
	a.Status = "connecting"
	a.Connection = ConnectionState{Stage: "Запуск ядра", StartedAt: time.Now().UnixMilli()}
	a.log(fmt.Sprintf("Подключение: %d доменов, локальный SOCKS5 127.0.0.1:%d", len(p.Domains), a.Port))
	a.log("Ядро запущено; проверка туннеля")
	go func() {
		defer close(done)
		defer os.RemoveAll(dir)
		defer job()
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			line := sc.Text()
			a.mu.Lock()
			a.runtimeEvent(line)
			a.mu.Unlock()
		}
		err := cmd.Wait()
		a.mu.Lock()
		defer a.mu.Unlock()
		if ctx.Err() != nil {
			a.Status = "disconnected"
			a.Connection.Stage = "Туннель остановлен"
			a.log("Туннель остановлен")
		} else {
			a.Status = "error"
			a.Connection.Stage = "Ядро завершилось; подключение отсутствует"
			if err != nil {
				a.log("Ядро завершилось с ошибкой. Проверьте ключ, домены и резолверы")
			} else {
				a.log("Ядро неожиданно завершилось")
			}
		}
		a.cancel = nil
	}()
	return nil
}
func (a *App) stop(scan bool) {
	a.mu.Lock()
	cancel, done := a.cancel, a.done
	if scan {
		cancel, done = a.scanCancel, a.scanDone
	}
	if cancel != nil {
		cancel()
	}
	a.mu.Unlock()
	if cancel != nil {
		<-done
	}
}
func (a *App) scan(domain string, resolvers []string, workers int) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy() {
		return fmt.Errorf("остановите подключение или текущую проверку")
	}
	if workers < 1 || workers > 128 {
		return fmt.Errorf("число параллельных проверок должно быть от 1 до 128")
	}
	p, err := a.current()
	if err != nil {
		return err
	}
	exists := false
	for _, d := range p.Domains {
		if d == domain {
			exists = true
		}
	}
	if !exists {
		return fmt.Errorf("домен отсутствует в профиле")
	}
	resolvers, err = profile.NormalizeResolvers(resolvers)
	if err != nil {
		return err
	}
	if len(resolvers) == 0 || len(resolvers) > 100000 {
		return fmt.Errorf("укажите от 1 до 100000 адресов")
	}
	ctx, cancel := context.WithTimeout(a.root, 30*time.Minute)
	a.scanCancel = cancel
	a.scanDone = make(chan struct{})
	done := a.scanDone
	a.ScanWorkers = workers
	if err := a.persist(); err != nil {
		cancel()
		a.scanCancel = nil
		close(done)
		return fmt.Errorf("не удалось сохранить число потоков")
	}
	a.Scan = ScanState{Running: true, Domain: domain, Results: []Result{}, Total: len(resolvers), Workers: workers}
	a.log("Начата проверка рабочих резолверов")
	go func() {
		defer close(done)
		defer cancel()
		var failure string
		// Bounded batches retain results if a later batch times out or is cancelled.
		for i := 0; i < len(resolvers) && ctx.Err() == nil; i += workers {
			end := i + workers
			if end > len(resolvers) {
				end = len(resolvers)
			}
			batch := resolvers[i:end]
			dir, err := a.runtimeFiles(p, []string{domain}, map[string][]string{domain: batch}, a.Port)
			if err != nil {
				failure = "Ошибка конфигурации сканера"
				break
			}
			cmd := a.command(ctx, dir, true)
			cmd.Args = append(cmd.Args, "-scan-workers", strconv.Itoa(workers))
			out, err := cmd.StdoutPipe()
			if err != nil {
				os.RemoveAll(dir)
				failure = "Не удалось открыть вывод ядра"
				break
			}
			cmd.Stderr = io.Discard
			if err = cmd.Start(); err != nil {
				os.RemoveAll(dir)
				failure = "Не удалось запустить сканер"
				break
			}
			job, err := childJob(cmd.Process.Pid)
			if err != nil {
				cmd.Process.Kill()
				cmd.Wait()
				os.RemoveAll(dir)
				failure = "Не удалось защитить процесс сканера"
				break
			}
			complete := false
			sc := bufio.NewScanner(out)
			for sc.Scan() {
				line := sc.Text()
				if strings.HasPrefix(line, "TUNA_SCAN_PROGRESS ") {
					var finished, total int
					if n, e := fmt.Sscanf(line, "TUNA_SCAN_PROGRESS %d %d", &finished, &total); e == nil && n == 2 && total == len(batch) && finished >= 0 && finished <= total {
						a.mu.Lock()
						if i+finished > a.Scan.Done {
							a.Scan.Done = i + finished
						}
						a.mu.Unlock()
					}
				}
				if line == "TUNA_SCAN_DONE" {
					complete = true
				}
				if strings.HasPrefix(line, "TUNA_RESOLVER ") {
					var r Result
					if json.Unmarshal([]byte(strings.TrimPrefix(line, "TUNA_RESOLVER ")), &r) == nil && r.Domain == domain {
						a.mu.Lock()
						a.Scan.Results = append(a.Scan.Results, r)
						a.mu.Unlock()
					}
				}
			}
			err = cmd.Wait()
			job()
			os.RemoveAll(dir)
			if err != nil || !complete {
				failure = "Проверка завершилась не полностью; сохранены полученные результаты"
				break
			}
			a.mu.Lock()
			a.Scan.Done = end
			a.mu.Unlock()
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if ctx.Err() != nil {
			failure = "Проверка остановлена"
		}
		a.Scan.Running = false
		a.Scan.Error = failure
		a.scanCancel = nil
		a.log("Проверка резолверов завершена")
	}()
	return nil
}

type Request struct {
	Workers   int             `json:"workers"`
	Action    string          `json:"action"`
	Link      string          `json:"link"`
	Index     int             `json:"index"`
	Domain    string          `json:"domain"`
	Resolvers []string        `json:"resolvers"`
	URL       string          `json:"url"`
	Kind      string          `json:"kind"`
	Full      bool            `json:"full"`
	Profile   profile.Profile `json:"profile"`
	Port      int             `json:"port"`
}

func (a *App) action(ctx context.Context, r Request) (any, error) {
	switch r.Action {
	case "state":
		return a.snapshot(), nil
	case "connect":
		if err := a.start(); err != nil {
			return nil, err
		}
		return a.snapshot(), nil
	case "disconnect":
		a.stop(false)
		return a.snapshot(), nil
	case "scan":
		if r.Workers == 0 {
			r.Workers = 32
		}
		if err := a.scan(r.Domain, r.Resolvers, r.Workers); err != nil {
			return nil, err
		}
		return a.snapshot(), nil
	case "cancelScan":
		a.stop(true)
		return a.snapshot(), nil
	case "probe":
		s := a.snapshot()
		if s.Status != "connected" {
			return nil, fmt.Errorf("сначала подключите туннель")
		}
		msg, err := probe(ctx, s.Port)
		return map[string]string{"message": msg}, err
	case "export":
		s := a.snapshot()
		text, err := profile.Export(r.Kind, r.Full, s.Port)
		return map[string]string{"text": text}, err
	case "database":
		return downloadDB(ctx, r.URL)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.busy() && r.Action != "clearLog" {
		return nil, fmt.Errorf("сначала остановите туннель и сканирование")
	}
	// Roll back in-memory changes if persistence fails.
	old, _ := json.Marshal(a.State)
	switch r.Action {
	case "import":
		p, err := profile.Parse(r.Link)
		if err != nil {
			return nil, err
		}
		if len(a.Profiles) >= 100 {
			return nil, fmt.Errorf("достигнут лимит 100 профилей")
		}
		a.Profiles = append(a.Profiles, p)
		a.Selected = len(a.Profiles) - 1
		a.Scan = ScanState{Results: []Result{}}
		a.log("Профиль импортирован")
	case "select":
		if r.Index < 0 || r.Index >= len(a.Profiles) {
			return nil, fmt.Errorf("нет такого профиля")
		}
		a.Selected = r.Index
		a.Scan = ScanState{Results: []Result{}}
	case "delete":
		if r.Index < 0 || r.Index >= len(a.Profiles) {
			return nil, fmt.Errorf("нет такого профиля")
		}
		a.Profiles = append(a.Profiles[:r.Index], a.Profiles[r.Index+1:]...)
		a.Selected = 0
		a.Scan = ScanState{Results: []Result{}}
	case "selectResolvers", "resetResolvers":
		p, err := a.current()
		if err != nil {
			return nil, err
		}
		found := false
		for _, d := range p.Domains {
			if d == r.Domain {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("нет такого домена")
		}
		if p.Selected == nil {
			p.Selected = map[string][]string{}
		}
		if r.Action == "resetResolvers" {
			delete(p.Selected, r.Domain)
		} else {
			rr, err := profile.NormalizeResolvers(r.Resolvers)
			if err != nil || len(rr) == 0 {
				return nil, fmt.Errorf("выберите рабочие резолверы")
			}
			p.Selected[r.Domain] = rr
		}
		if err = p.Validate(); err != nil {
			json.Unmarshal(old, &a.State)
			return nil, err
		}
		a.Profiles[a.Selected] = p
	case "settings":
		if _, err := a.current(); err != nil {
			return nil, err
		}
		if r.Port < 1024 || r.Port > 65535 {
			return nil, fmt.Errorf("порт должен быть 1024–65535")
		}
		if err := r.Profile.Validate(); err != nil {
			return nil, err
		}
		a.Profiles[a.Selected] = r.Profile
		a.Port = r.Port
	case "clearLog":
		a.Logs = []string{}
	default:
		return nil, fmt.Errorf("неизвестное действие")
	}
	if err := a.persist(); err != nil {
		json.Unmarshal(old, &a.State)
		return nil, fmt.Errorf("не удалось сохранить настройки")
	}
	raw, _ := json.Marshal(a.State)
	var state State
	json.Unmarshal(raw, &state)
	return state, nil
}
func downloadDB(ctx context.Context, address string) (any, error) {
	valid := func(s string) bool {
		u, e := url.Parse(s)
		return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
	}
	if !valid(address) {
		return nil, fmt.Errorf("укажите HTTPS-адрес текстовой базы")
	}
	cl := http.Client{Timeout: 30 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 4 || !valid(r.URL.String()) {
			return fmt.Errorf("недопустимое перенаправление")
		}
		return nil
	}}
	req, _ := http.NewRequestWithContext(ctx, "GET", address, nil)
	res, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("не удалось скачать базу")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("сервер базы вернул HTTP %d", res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 2*1024*1024+1))
	if err != nil || len(b) > 2*1024*1024 {
		return nil, fmt.Errorf("база слишком большая или не прочитана")
	}
	var candidates []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line != "" {
			candidates = append(candidates, line)
		}
	}
	rr, err := profile.NormalizeResolvers(candidates)
	if err != nil {
		return nil, fmt.Errorf("база должна содержать только IP[:порт], по одному адресу на строку")
	}
	if len(rr) == 0 || len(rr) > 100000 {
		return nil, fmt.Errorf("база должна содержать 1–100000 адресов")
	}
	return map[string]any{"resolvers": rr}, nil
}
