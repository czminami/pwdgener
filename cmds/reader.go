/*
Copyright github.com/czminami. All Rights Reserved.
SPDX-License-Identifier: GPL-3.0-or-later
*/

package cmds

import (
	"fmt"
	"io/ioutil"

	"github.com/czminami/m41pg/util"
	"github.com/czminami/pwdgener/crypto"
	"github.com/spf13/cobra"
)

var (
	Key string
)

func init() {
	ReaderCmd.Flags().StringVar(&Key, "key", "", "encrypted password file")
}

var ReaderCmd = &cobra.Command{
	Use:   "read",
	Short: "Read Encrypted Password",
	Run: func(cmd *cobra.Command, args []string) {
		payload, err := ioutil.ReadFile(Key)
		if err != nil {
			logger.Error(err)
			return
		}

		pwd, err := util.ScanEncPwd(false)
		if err != nil {
			return
		}

		raw, err := crypto.Decrypt(pwd, payload)
		if err != nil {
			return
		}

		fmt.Print(string(raw))
	},
}
