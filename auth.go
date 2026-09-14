package main

import (
	"context"
	"crypto/rand"
	"net/http"
	"strconv"

	pkgerr "github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/crypto/bcrypt"
)

type contextKey string

const UserContextKey contextKey = "user"

var allowedUsers = map[string]string{
	"frodo":   "$2a$10$B6O/n6teuCzpuh66jrUAdeaJ3WvXcxRkzpN0x7H.di9G9e/NGb9Me",
	"samwise": "$2a$10$EWZpvYhUJtJcEMmm/IBOsOGIcpxUnGIVMRiDlN/nxl1RRwWGkJtty",
	// frodo: "ofTheNineFingers"
	// samwise: "theStrong"
	"saruman": "invalidFormat",
}

func (s *server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			httpError(r.Context(), w, http.StatusUnauthorized, pkgerr.Errorf("unauthorized"))
			return
		}
		stored, exists := allowedUsers[username]
		if !exists {
			httpError(r.Context(), w, http.StatusUnauthorized, pkgerr.Errorf("unauthorized"))
			return
		}
		ok, err := s.validatePassword(r.Context(), password, stored)
		if err != nil {
			s.logger.Error(
				"error validating password",
				"usaer", username,
				"error", err,
			)
			httpError(r.Context(), w, http.StatusInternalServerError, pkgerr.Errorf("internal server error"))
			return
		}
		if !ok {
			httpError(r.Context(), w, http.StatusUnauthorized, pkgerr.Errorf("unauthorized"))
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), UserContextKey, username))

		logContext, ok := r.Context().Value(logContextKey).(*LogContext)
		if !ok {
			httpError(r.Context(), w, http.StatusInternalServerError, pkgerr.Errorf("internal server error"))
			return
		}
		logContext.Username = username

		next.ServeHTTP(w, r)
	})
}

func (s *server) validatePassword(ctx context.Context, password, stored string) (bool, error) {
	_, span := trcr.Start(ctx, "auth.validate_password")
	defer span.End()
	err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	if err != nil {
		return false, pkgerr.WithStack(err)
	}
	return true, nil
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		requestID := r.Header.Get("X-Request-ID")

		if requestID == "" {

			requestID = rand.Text()
		}

		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r)
	})
}

// httpRequestsTotal counts requests by method, path and status.
var httpRequestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of HTTP requests.",
	},
	[]string{"method", "path", "status"},
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{
			ResponseWriter: w,
			status:         http.StatusOK,
		}

		next.ServeHTTP(rec, r)

		path := r.URL.Path
		method := r.Method
		status := strconv.Itoa(rec.status)

		httpRequestsTotal.
			WithLabelValues(method, path, status).
			Inc()
	})
}
