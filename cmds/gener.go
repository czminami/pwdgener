/*
Copyright github.com/czminami. All Rights Reserved.
SPDX-License-Identifier: GPL-3.0-or-later
*/

package cmds

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/czminami/m41pg/util"
	"github.com/czminami/pwdgener/crypto"
	"github.com/op/go-logging"
	"github.com/spf13/cobra"
)

var (
	logger = logging.MustGetLogger("gener")

	Source = []string{
		"0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
		"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
		"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
	}

	Special = []string{
		`!`, `@`, `#`, `$`, `%`, `&`, `*`, `-`, `+`, `=`, `?`, `<`, `>`, `[`, `]`, "{", "}",
	}

	WithSpec     bool
	Security     int
	SecurityUnit int
	Desc         string
)

func init() {
	GenerCmd.Flags().BoolVar(&WithSpec, "spec", false, "with special characters")
	GenerCmd.Flags().IntVar(&Security, "security", 20, "password security")
	GenerCmd.Flags().IntVar(&SecurityUnit, "unit", 5, "unit appear atleast times")
	GenerCmd.Flags().StringVar(&Desc, "desc", "XXX password", "describe")
}

var GenerCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate New Password",
	Args: func(cmd *cobra.Command, args []string) error {
		unit := func() int {
			if WithSpec {
				return 4

			} else {
				return 3
			}
		}

		if SecurityUnit*unit() > Security {
			return errors.New("unit exceed security")
		}

		return nil
	},

	Run: func(cmd *cobra.Command, args []string) {
		if WithSpec {
			Source = append(Source, Special...)
		}

		var pwd []byte
		for pwd == nil {
			pwd = generatePwd(Security, SecurityUnit, WithSpec)
		}

		encPwd, err := util.ScanEncPwd(true)
		if err != nil {
			return
		}

		keyName, err := crypto.Encrypt(encPwd, pwd, Desc)
		if err != nil {
			return
		}

		fmt.Println(fmt.Sprintf("\nThe password is saved in the %s file.", keyName))
	},
}

func generatePwd(security, unit int, withSpec bool) []byte {
	chaotic := []byte(strings.Join(shuffle(shuffle(append(shuffle(Source, 100), shuffle(Source, 100)...), 100), 100), ""))

	var pwd []byte
	var rest []byte

	var illegal []byte
	var ok bool

	var loop int

	for {
		if len(chaotic) == 0 {
			chaotic = rest
			rest = nil

		} else if (security - len(pwd)) > len(chaotic) {
			chaotic = append(chaotic, rest...)
			rest = nil
		}

		if len(pwd) != security {
			needed := security - len(pwd)
			pwd = append(pwd, chaotic[:needed]...)
			chaotic = chaotic[needed:]
		}

		pwd, illegal, ok = matchingRules(pwd, unit, withSpec)
		if ok {
			break
		}

		rest = append(rest, illegal...)

		if loop += 1; loop == 100 {
			return nil
		}
	}

	return pwd
}

func shuffle(source []string, thousands int) []string {
	random := bytes.NewBuffer(nil)

	buf := make([]byte, 16)
	for random.Len() <= 1000*thousands {
		io.ReadFull(rand.Reader, buf)
		random.WriteString(big.NewInt(0).SetBytes(buf).String())
	}

	original := make([]string, len(source))
	copy(original, source)

	var cursor int
	var chaotic []string

	for _, v := range random.String() {
		if len(original) == 0 {
			original = chaotic
			chaotic = nil
		}

		offset, _ := strconv.Atoi(string(v))
		if cursor += offset; cursor >= len(original) {
			cursor = cursor % len(original)
		}

		chaotic = append(chaotic, original[cursor])
		original = append(original[:cursor], original[cursor+1:]...)
	}

	return append(chaotic, original...)
}

func matchingRules(password []byte, unit int, withSpec bool) ([]byte, []byte, bool) {
	pwd := make([]byte, len(password))
	copy(pwd, password)

	isSpecial := make(map[byte]byte, len(Special))
	for _, c := range []byte(strings.Join(Special, "")) {
		isSpecial[c] = 1
	}

	numerical := 0
	upperCharacter := 0
	lowerCharacter := 0
	special := 0

	for _, char := range pwd {
		if isNumerical(char) {
			numerical += 1

		} else if isUpperCharacter(char) {
			upperCharacter += 1

		} else if isLowerCharacter(char) {
			lowerCharacter += 1

		} else if _, ok := isSpecial[char]; ok {
			special += 1
		}
	}

	if numerical < unit || upperCharacter < unit || lowerCharacter < unit {
		return pwd[1:], pwd[:1], false
	}

	if withSpec {
		if numerical < unit || upperCharacter < unit || lowerCharacter < unit || special < unit {
			return pwd[1:], pwd[:1], false
		}
	}

	return pwd, nil, true
}

func isNumerical(char byte) bool {
	return char >= byte('0') && char <= byte('9')
}

func isUpperCharacter(char byte) bool {
	return char >= byte('A') && char <= byte('Z')
}

func isLowerCharacter(char byte) bool {
	return char >= byte('a') && char <= byte('z')
}
