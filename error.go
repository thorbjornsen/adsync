package adsync

import "net/http"

type AzureError struct{
    Status string // e.g. "200 OK"
    Code   int    // e.g. 200

    Err    error
}

func (e *AzureError) Error() string {
    return e.Err.Error()
}

func (e *AzureError) Ok() bool {
    return e.Err == nil
}

func (e *AzureError) Unauthorized() bool {
    return e.Code == http.StatusUnauthorized
}

type RangerError struct{
    Status string // e.g. "200 OK"
    Code   int    // e.g. 200

    Err    error
}

func (e *RangerError) Error() string {
    return e.Err.Error()
}

func (e *RangerError) Ok() bool {
    return e.Err == nil
}

