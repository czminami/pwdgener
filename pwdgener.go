/*
Copyright github.com/czminami. All Rights Reserved.
SPDX-License-Identifier: GPL-3.0-or-later
*/

package main

import (
	"os"
	"runtime/debug"

	"github.com/czminami/pwdgener/cmds"
	"github.com/op/go-logging"
	"github.com/spf13/cobra"
)

var logger = logging.MustGetLogger("pwdgener")

func main() {
	format := logging.MustStringFormatter(`[%{module}] %{time:2006-01-02 15:04:05} [%{level}] [%{longpkg} %{shortfile}] { %{message} }`)

	backendConsole := logging.NewLogBackend(os.Stderr, "", 0)
	backendConsole2Formatter := logging.NewBackendFormatter(backendConsole, format)

	logging.SetBackend(backendConsole2Formatter)
	logging.SetLevel(logging.INFO, "")

	defer func() {
		if err := recover(); err != nil {
			logger.Error(err)
			logger.Info(string(debug.Stack()))
		}
	}()

	var rootCmd = &cobra.Command{
		Short:   "Minami Password Generator",
		Version: "0.0.1",
	}

	rootCmd.AddCommand(
		cmds.GenerCmd,
		cmds.ReaderCmd,
	)

	if err := rootCmd.Execute(); err != nil {
		logger.Error(err)
	}
}
