/*
Copyright github.com/czminami. All Rights Reserved.
SPDX-License-Identifier: GPL-3.0-or-later
*/

package crypto

import (
	"github.com/czminami/m41pg/crypto"
	"github.com/czminami/minami41"
)

func Decrypt(pwd []string, payload []byte) ([]byte, error) {
	_, raw, err := minami41.Decode(payload)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	_, encPwds, err := crypto.Chaos(pwd)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	raw, err = crypto.AesDecrypt(encPwds, raw)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	return raw, nil
}
