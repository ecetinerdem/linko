package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"net/http/pprof"
	_ "net/http/pprof"

	"boot.dev/linko/internal/store"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type server struct {
	httpServer *http.Server
	store      store.Store
	logger     *slog.Logger
	cancel     context.CancelFunc
}

func newServer(store store.Store, port int, logger *slog.Logger, cancel context.CancelFunc) *server {
	mux := http.NewServeMux()

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: otelhttp.NewHandler(metricsMiddleware(requestIDMiddleware(requestLogger(logger)(mux))), "http.server"),
	}

	s := &server{
		httpServer: srv,
		store:      store,
		logger:     logger,
		cancel:     cancel,
	}

	mux.HandleFunc("GET /", s.handlerIndex)
	mux.Handle("POST /api/login", s.authMiddleware(http.HandlerFunc(s.handlerLogin)))
	mux.Handle("POST /api/shorten", s.authMiddleware(http.HandlerFunc(s.handlerShortenLink)))
	mux.Handle("GET /api/stats", s.authMiddleware(http.HandlerFunc(s.handlerStats)))
	mux.Handle("GET /api/urls", s.authMiddleware(http.HandlerFunc(s.handlerListURLs)))
	mux.HandleFunc("GET /{shortCode}", s.handlerRedirect)
	mux.HandleFunc("POST /admin/shutdown", s.handlerShutdown)
	mux.Handle("GET /metrics", promhttp.Handler())
	mux.Handle("GET /debug/pprof/", s.authMiddleware(http.HandlerFunc(pprof.Index)))
	mux.Handle("GET /debug/pprof/profile", s.authMiddleware(http.HandlerFunc(pprof.Profile)))

	return s
}

func (s *server) start() error {
	ln, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return err
	}
	s.logger.Debug(fmt.Sprintf("Linko is running on http://localhost:%d", ln.Addr().(*net.TCPAddr).Port))
	if err := s.httpServer.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *server) shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *server) handlerShutdown(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("ENV") == "production" {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
	go s.cancel()
}

const logContextKey contextKey = "log_context"

type LogContext struct {
	Username string
	Error    error
}

type spyResponseWriter struct {
	http.ResponseWriter
	bytesWritten int
	statusCode   int
}

func (w *spyResponseWriter) Write(p []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytesWritten += n
	return n, err
}

func (w *spyResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

type spyReadCloser struct {
	io.ReadCloser
	bytesRead int
}

func (r *spyReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.bytesRead += n
	return n, err
}

func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			spyReader := &spyReadCloser{ReadCloser: r.Body}
			r.Body = spyReader

			spyWriter := &spyResponseWriter{ResponseWriter: w}

			logContext := &LogContext{}
			r = r.WithContext(context.WithValue(r.Context(), logContextKey, logContext))

			requestID := r.Header.Get("X-Request-ID")
			clientIPRedeacted, err := redactIP(r.RemoteAddr)
			if err != nil {
				clientIPRedeacted = "unknown"
			}
			start := time.Now()
			next.ServeHTTP(spyWriter, r)

			attrs := []slog.Attr{
				slog.String("request_id", requestID),
				slog.Duration("duration", time.Since(start)),
				slog.Int("request_body_bytes", spyReader.bytesRead),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("client_ip", clientIPRedeacted),
				slog.Int("response_status", spyWriter.statusCode),
				slog.Int("response_body_bytes", spyWriter.bytesWritten),
			}

			if logContext.Username != "" {
				attrs = append(attrs, slog.String("user", logContext.Username))
			}

			if logContext.Error != nil {

				errAttr := errorAttrs(logContext.Error)
				groupedAttr := slog.Attr{Key: "error", Value: slog.GroupValue(errAttr...)}
				attrs = append(attrs, groupedAttr)
			}

			logger.LogAttrs(
				r.Context(),
				slog.LevelInfo,
				"Served request",
				attrs...,
			)
		})
	}
}

func httpError(ctx context.Context, w http.ResponseWriter, status int, err error) {
	if logCtx, ok := ctx.Value(logContextKey).(*LogContext); ok {
		logCtx.Error = err
	}

	switch status {
	case 401:
		http.Error(w, http.StatusText(http.StatusUnauthorized), status)
	case 403:
		http.Error(w, http.StatusText(http.StatusForbidden), status)
	case 500:
		http.Error(w, http.StatusText(http.StatusInternalServerError), status)
	default:
		http.Error(w, err.Error(), status)
	}
}

func redactIP(ipAddr string) (string, error) {
	host, _, err := net.SplitHostPort(ipAddr)
	if err != nil {
		return "", err
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address")
	}

	if ip.To4() == nil {
		return ip.String(), nil
	}

	parts := strings.Split(ip.String(), ".")

	if len(parts) != 4 {
		return "", fmt.Errorf("invalid IP address")
	}

	parts[3] = "x"

	resultIP := strings.Join(parts, ".")

	return resultIP, nil
}
