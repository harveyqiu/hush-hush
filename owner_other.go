//go:build !unix

package main

import "os"

func checkOwner(os.FileInfo) error { return nil }
