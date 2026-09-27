package kernel

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/oarkflow/velocity/v2/api"
)

// stdLogger is the default api.Logger implementation: a thin leveled
// wrapper over the standard library logger. It exists so the kernel and
// every plugin have a working logger out of the box with zero external
// dependencies; a plugin (or cmd/velocityd) wanting structured/JSON
// logging can swap this out by implementing api.Logger itself.
type stdLogger struct {
	l *log.Logger
}

func newLogger() *stdLogger {
	return &stdLogger{l: log.New(os.Stderr, "", log.LstdFlags)}
}

func (s *stdLogger) log(level, msg string, kv ...any) {
	if len(kv) == 0 {
		s.l.Printf("[%s] %s", level, msg)
		return
	}
	pairs := make([]string, 0, len(kv)/2+1)
	for i := 0; i+1 < len(kv); i += 2 {
		pairs = append(pairs, fmt.Sprintf("%v=%v", kv[i], kv[i+1]))
	}
	if len(kv)%2 == 1 {
		pairs = append(pairs, fmt.Sprintf("%v", kv[len(kv)-1]))
	}
	s.l.Printf("[%s] %s %s", level, msg, strings.Join(pairs, " "))
}

func (s *stdLogger) Debug(msg string, kv ...any) { s.log("DEBUG", msg, kv...) }
func (s *stdLogger) Info(msg string, kv ...any)  { s.log("INFO", msg, kv...) }
func (s *stdLogger) Warn(msg string, kv ...any)  { s.log("WARN", msg, kv...) }
func (s *stdLogger) Error(msg string, kv ...any) { s.log("ERROR", msg, kv...) }

var _ api.Logger = (*stdLogger)(nil)
