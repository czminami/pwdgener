/*
Copyright github.com/czminami. All Rights Reserved.
SPDX-License-Identifier: GPL-3.0-or-later
*/

package crypto

import (
	"os"

	"github.com/czminami/m41pg/crypto"
	"github.com/czminami/minami41"
	"github.com/op/go-logging"
)

var logger = logging.MustGetLogger("crypto")

func Encrypt(pwd []string, payload []byte, desc string) (string, error) {
	_, encPwds, err := crypto.Chaos(pwd)
	if err != nil {
		logger.Error(err)
		return "", err
	}

	raw, err := crypto.AecEncrypt(encPwds, payload)
	if err != nil {
		logger.Error(err)
		return "", err
	}

	raw, err = minami41.Encode(raw, desc)
	if err != nil {
		logger.Error(err)
		return "", err
	}

	keyName := desc + ".key"
	key, err := os.OpenFile(keyName, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0666)
	if err != nil {
		logger.Error(err)
		return "", err
	}
	defer key.Close()

	if _, err = key.Write(raw); err != nil {
		logger.Error(err)
		return "", err
	}

	return keyName, nil
}
