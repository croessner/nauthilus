package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
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
			if content, err := ioutil.ReadAll(resp.Body); err != nil {
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
