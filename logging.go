package adsync

import (
    "fmt"
    "log"
)

type LevelType int

const (
    DEBUG LevelType = iota
    INFO
    WARN
    ERROR
    FATAL
)

type Logger struct {
    Level LevelType
}

var logger = &Logger{ Level: INFO }

func (l *Logger) isDebug() bool {
    if l.Level > DEBUG {
        return false
    }

    return true
}

func (l *Logger) Debug(v ...interface{}) {
    if l.Level > DEBUG {
        return
    }

    log.Println( "Debug: ", fmt.Sprint(v...) )
}

func (l *Logger) Info(v ...interface{}) {
    if l.Level > INFO {
        return
    }

    log.Println( "Info: ", fmt.Sprint(v...) )
}

func (l *Logger) Warn(v ...interface{}) {
    if l.Level > WARN {
        return
    }

    log.Println( "Warn: ", fmt.Sprint(v...) )
}

func (l *Logger) Error(v ...interface{}) {
    if l.Level > ERROR {
        return
    }

    log.Println( "Error: ", fmt.Sprint(v...) )
}

func (l *Logger) Fatal(v ...interface{}) {
    log.Fatalln( "Fatal: ", fmt.Sprint(v...) )
}

