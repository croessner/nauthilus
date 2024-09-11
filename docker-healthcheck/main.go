// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const nauthilusURL = "http://127.0.0.1:9080/ping"

func main() {
	pflag.StringP("url", "u", nauthilusURL, "nauthilus url to test")
	pflag.BoolP("verbose", "v", false, "Be verbose")
	pflag.BoolP("tls-skip-verify", "t", false, "Skip TLS server certificate verification")
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)

	if viper.GetBool("verbose") {
		fmt.Println("Checking", viper.GetString("url"))
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: viper.GetBool("tls-skip-verify")},
	}
	httpClient := http.Client{Timeout: time.Second * 10, Transport: transport}
	if resp, err := httpClient.Get(viper.GetString("url")); err != nil {
		if viper.GetBool("verbose") {
			fmt.Println("Test FAILED")
		}
		os.Exit(1)
	} else {
		if resp.StatusCode == http.StatusOK {
			if content, err := io.ReadAll(resp.Body); err != nil {
				fmt.Println("Test FAILED")
			} else {
				if strings.ToLower(string(content)) == "pong" {
					if viper.GetBool("verbose") {
						fmt.Println("Test OK")
					}
				} else {
					fmt.Println("Test FAILED")
				}
			}
		} else {
			if viper.GetBool("verbose") {
				fmt.Println("Test FAILED")
			}
			os.Exit(1)
		}
	}
	os.Exit(0)
}
