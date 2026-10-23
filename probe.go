package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// DNS for the target is resolved by the SOCKS server, never by the physical connection.
func socksDial(proxy string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		p, err := strconv.Atoi(port)
		if err != nil || len(host) == 0 || len(host) > 255 || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid target")
		}
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxy)
		if err != nil {
			return nil, fmt.Errorf("SOCKS5 недоступен")
		}
		ok := false
		defer func() {
			if !ok {
				c.Close()
			}
		}()
		deadline := time.Now().Add(25 * time.Second)
		if d, yes := ctx.Deadline(); yes && d.Before(deadline) {
			deadline = d
		}
		c.SetDeadline(deadline)
		cancel := context.AfterFunc(ctx, func() { c.Close() })
		defer cancel()
		if _, err = c.Write([]byte{5, 1, 0}); err != nil {
			return nil, err
		}
		b := make([]byte, 2)
		if _, err = io.ReadFull(c, b); err != nil {
			return nil, err
		}
		if b[0] != 5 || b[1] != 0 {
			return nil, fmt.Errorf("SOCKS5 отклонил метод авторизации")
		}
		req := append([]byte{5, 1, 0, 3, byte(len(host))}, []byte(host)...)
		req = binary.BigEndian.AppendUint16(req, uint16(p))
		if _, err = c.Write(req); err != nil {
			return nil, err
		}
		header := make([]byte, 4)
		if _, err = io.ReadFull(c, header); err != nil {
			return nil, err
		}
		if header[0] != 5 || header[1] != 0 || header[2] != 0 {
			return nil, fmt.Errorf("SOCKS5 не смог установить соединение")
		}
		n := 0
		switch header[3] {
		case 1:
			n = 4
		case 4:
			n = 16
		case 3:
			if _, err = io.ReadFull(c, b[:1]); err != nil {
				return nil, err
			}
			n = int(b[0])
		default:
			return nil, fmt.Errorf("invalid SOCKS reply")
		}
		if _, err = io.CopyN(io.Discard, c, int64(n+2)); err != nil {
			return nil, err
		}
		c.SetDeadline(time.Time{})
		ok = true
		return c, nil
	}
}
func probe(ctx context.Context, port int) (string, error) {
	tr := &http.Transport{DialContext: socksDial(net.JoinHostPort("127.0.0.1", strconv.Itoa(port))), TLSHandshakeTimeout: 20 * time.Second, ResponseHeaderTimeout: 25 * time.Second}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 35 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.cloudflare.com/cdn-cgi/trace", nil)
	start := time.Now()
	res, err := cl.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTPS через SOCKS5 не прошёл: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 16385))
	if err != nil {
		return "", err
	}
	if res.StatusCode != 200 || len(body) > 16384 {
		return "", fmt.Errorf("неожиданный ответ HTTPS: %d", res.StatusCode)
	}
	return fmt.Sprintf("HTTPS через туннель работает. TLS проверен; ответ получен за %.1f с.", time.Since(start).Seconds()), nil
}
