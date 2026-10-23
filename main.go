package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	webview "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"
	"unsafe"
)

//go:embed web/index.html assets/core.exe
var resources embed.FS

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		msg, _ := windows.UTF16PtrFromString(err.Error())
		title, _ := windows.UTF16PtrFromString("TUNA DNS Client")
		windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(msg)), uintptr(unsafe.Pointer(title)), 0x10)
		os.Exit(1)
	}
}
func run() error {
	serve := flag.Bool("serve", false, "Open UI in a browser manually (diagnostics)")
	data := flag.String("data-dir", "", "Private profile directory override")
	listen := flag.String("listen", "127.0.0.1:0", "Loopback UI listen address")
	flag.Parse()
	dir := *data
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		dir = filepath.Join(base, "TUNA DNS Client")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err = privateDir(dir); err != nil {
		return fmt.Errorf("не удалось защитить папку данных: %w", err)
	}
	hash := sha256.Sum256([]byte(dir))
	name, _ := windows.UTF16PtrFromString("Local\\TunaDNSClient-" + hex.EncodeToString(hash[:12]))
	mutex, err := windows.CreateMutex(nil, false, name)
	if err == windows.ERROR_ALREADY_EXISTS {
		if mutex != 0 {
			windows.CloseHandle(mutex)
		}
		return fmt.Errorf("TUNA DNS Client уже запущен")
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(mutex)
	// Remove only our own abandoned transient directories, after obtaining the single-instance lock.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() && len(e.Name()) > 4 && e.Name()[:4] == "run-" {
			if err = os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	raw, err := resources.ReadFile("assets/core.exe")
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	core := filepath.Join(dir, "tuna-dns-core.exe")
	existing, _ := os.ReadFile(core)
	if sha256.Sum256(existing) != sum {
		if err = os.WriteFile(core, raw, 0600); err != nil {
			return err
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	app, err := newApp(ctx, dir, core)
	if err != nil {
		return err
	}
	defer app.stop(true)
	defer app.stop(false)
	tokenBytes := make([]byte, 32)
	if _, err = rand.Read(tokenBytes); err != nil {
		return err
	}
	token := hex.EncodeToString(tokenBytes)
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || host != "127.0.0.1" {
		return fmt.Errorf("интерфейс может слушать только 127.0.0.1")
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	origin := "http://" + listener.Addr().String()
	html, err := resources.ReadFile("web/index.html")
	if err != nil {
		return err
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		if r.Host != listener.Addr().String() {
			http.Error(w, "Forbidden", 403)
			return
		}
		if r.URL.Path == "/" && r.Method == "GET" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(html)
			return
		}
		if r.URL.Path != "/api" || r.Method != "POST" {
			http.NotFound(w, r)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Tuna-Token")), []byte(token)) != 1 || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != origin) {
			http.Error(w, "Forbidden", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		r.Body = http.MaxBytesReader(w, r.Body, 2*1024*1024)
		dec := json.NewDecoder(r.Body)
		var req Request
		if err := dec.Decode(&req); err != nil {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "Некорректный запрос"})
			return
		}
		if dec.Decode(new(any)) != io.EOF {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "Лишние данные запроса"})
			return
		}
		value, err := app.action(r.Context(), req)
		if err != nil {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(value)
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 30 * time.Second}
	defer server.Close()
	go server.Serve(listener)
	address := origin + "/#" + token
	if *serve {
		fmt.Println(address)
		<-ctx.Done()
		return nil
	}
	view := webview.NewWithOptions(webview.WebViewOptions{Debug: false, AutoFocus: true, DataPath: filepath.Join(dir, "webview"), WindowOptions: webview.WindowOptions{Title: "TUNA DNS Client", Width: 1120, Height: 820, Center: true}})
	if view == nil {
		return fmt.Errorf("не удалось открыть окно. Установите Microsoft Edge WebView2 Runtime")
	}
	defer view.Destroy()
	view.SetSize(760, 600, webview.HintMin)
	view.Navigate(address)
	go func() { <-ctx.Done(); view.Terminate() }()
	view.Run()
	cancel()
	return nil
}
