package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
	"github.com/natefinch/lumberjack"
	pkgerr "github.com/pkg/errors"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracer "go.opentelemetry.io/otel/trace"

	"boot.dev/linko/internal/build"
	"boot.dev/linko/internal/linkoerr"
	"boot.dev/linko/internal/store"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	httpPort := flag.Int("port", 8899, "port to listen on")
	dataDir := flag.String("data", "./data", "directory to store data")
	flag.Parse()

	status := run(ctx, cancel, *httpPort, *dataDir)
	cancel()
	os.Exit(status)
}

var trcr tracer.Tracer

func run(ctx context.Context, cancel context.CancelFunc, httpPort int, dataDir string) int {

	shutDown, err := initTracing(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize tracer: %v\n", err)
		return 1
	}

	defer func() error {
		err := shutDown(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to close tracer: %v\n", err)
			return err
		}
		return nil
	}()

	logger, closerFunc, err := initializeLogger()

	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		return 1
	}

	defer func() error {
		err := closerFunc()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to close logger: %v\n", err)
			return err
		}
		return nil
	}()

	env := os.Getenv("ENV")
	hostname, _ := os.Hostname()

	logger = logger.With(
		slog.String("git_sha", build.GitSHA),
		slog.String("build_time", build.BuildTime),
		slog.String("env", env),
		slog.String("hostname", hostname),
	)

	st, err := store.New(dataDir, logger)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create store: %v", err))
		return 1
	}
	s := newServer(*st, httpPort, logger, cancel)
	var serverErr error
	go func() {
		serverErr = s.start()
	}()

	logger.Debug(fmt.Sprintf("Linko is running on http://localhost:%d", httpPort))

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.shutdown(shutdownCtx); err != nil {
		logger.Error(fmt.Sprintf("failed to shutdown server: %v", err))
		return 1
	}
	if serverErr != nil {
		logger.Error(fmt.Sprintf("server error: %v", serverErr))
		return 1
	}
	logger.Debug("Linko is shutting down")
	return 0
}

func initTracing(ctx context.Context) (func(context.Context) error, error) {
	exp, err := otlptracegrpc.New(ctx)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp,
			sdktrace.WithBatchTimeout(2*time.Second),
		),
		sdktrace.WithResource(resource.Default()),
	)

	otel.SetTracerProvider(tp)
	trcr = tp.Tracer("boot.dev/linko")
	return tp.Shutdown, nil
}

type stackTracer interface {
	error
	StackTrace() pkgerr.StackTrace
}

type closeFunc func() error

func initializeLogger() (*slog.Logger, closeFunc, error) {

	logFile, exists := os.LookupEnv("LINKO_LOG_FILE")

	if !exists {
		slog.Info("log file does not exist")
		return slog.New(slog.NewTextHandler(os.Stderr, nil)), func() error {
			return nil
		}, nil
	}

	logger := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    1,
		MaxAge:     28,
		MaxBackups: 10,
		LocalTime:  false,
		Compress:   true,
	}

	debugHandler := tint.NewTextHandler(os.Stderr, &tint.Options{
		Level:       slog.LevelDebug,
		ReplaceAttr: replaceAttr,
		NoColor:     !(isatty.IsCygwinTerminal(os.Stderr.Fd()) || isatty.IsTerminal(os.Stderr.Fd())),
	})

	infoHandler := slog.NewJSONHandler(logger, &slog.HandlerOptions{
		Level:       slog.LevelInfo,
		ReplaceAttr: replaceAttr,
	})

	sLogger := slog.New(slog.NewMultiHandler(
		debugHandler,
		infoHandler,
	))

	return sLogger, func() error {
		err := logger.Close()
		if err != nil {
			return err
		}
		return nil
	}, nil
}

type multiError interface {
	error
	Unwrap() []error
}

var sensitiveKeys = []string{"user", "password", "key", "apikey", "secret", "pin", "creditcardno"}

func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	if a.Key == "error" {
		err, ok := a.Value.Any().(error)
		if !ok {
			return a
		}

		var atrs []slog.Attr
		if multiErr, ok := errors.AsType[multiError](err); ok {
			errs := multiErr.Unwrap()
			for i, e := range errs {
				attrs := errorAttrs(e)
				atrs = append(atrs, slog.GroupAttrs(fmt.Sprintf("error_%d", i+1), attrs...))
			}
			return slog.GroupAttrs("errors", atrs...)
		}

		attrs := errorAttrs(err)
		return slog.GroupAttrs("error", attrs...)
	}

	if slices.Contains(sensitiveKeys, strings.ToLower(a.Key)) {
		return slog.String(a.Key, "[REDACTED]")
	}

	parsedUrl, err := url.Parse(a.Value.String())
	if err != nil {
		return a
	}

	if parsedUrl.User != nil {
		_, ok := parsedUrl.User.Password()
		if ok {
			userInfo := url.UserPassword(parsedUrl.User.Username(), "[REDACTED]")
			parsedUrl.User = userInfo
			return slog.String(a.Key, parsedUrl.String())
		}

	}

	return a
}

func errorAttrs(err error) []slog.Attr {
	attrs := []slog.Attr{slog.String("message", err.Error())}

	if stackErr, ok := errors.AsType[stackTracer](err); ok {
		attrs = append(attrs, slog.String("stack_trace", fmt.Sprintf("%+v", stackErr.StackTrace())))
	}

	linkoerrAttrs := linkoerr.Attrs(err)
	attrs = append(attrs, linkoerrAttrs...)
	return attrs

}
