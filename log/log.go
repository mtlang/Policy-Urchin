// Package log - Logger abstraction
package log

// Logger - A generic wrapper interface
type Logger interface {
	Debugf(string, ...interface{})
	Debug(args ...interface{})
	Errorf(string, ...interface{})
	Error(args ...interface{})
	Fatalf(string, ...interface{})
	Fatal(args ...interface{})
	Infof(string, ...interface{})
	Info(args ...interface{})
	Warnf(string, ...interface{})
	Warn(args ...interface{})
}
