package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/samber/lo"
	"github.com/samber/mo"
	"github.com/spf13/cobra"
)

var (
	configurationUseECDSA       bool
	configurationMitMAll        bool
	configurationNoMitM         bool
	configurationMitMHosts      []string
	configurationMitMExtraHosts []string
)

func init() {
	configurationUseECDSA = os.Getenv("DEMODEL_PROXY_CA_USE_ECDSA") == "true" || os.Getenv("DEMODEL_PROXY_CA_USE_ECDSA") == "1"
	configurationMitMAll = os.Getenv("DEMODEL_PROXY_MITM_ALL") == "true" || os.Getenv("DEMODEL_PROXY_MITM_ALL") == "1"
	configurationNoMitM = os.Getenv("DEMODEL_PROXY_NO_MITM") == "true" || os.Getenv("DEMODEL_PROXY_NO_MITM") == "1"
	configurationMitMHosts = strings.Split(os.Getenv("DEMODEL_PROXY_MITM_HOSTS"), ",")
	configurationMitMExtraHosts = strings.Split(os.Getenv("DEMODEL_PROXY_MITM_EXTRA_HOSTS"), ",")

	if len(configurationMitMHosts) > 0 {
		hosts = lo.Uniq(configurationMitMHosts)
	}
	if len(configurationMitMExtraHosts) > 0 {
		hosts = append(hosts, lo.Uniq(configurationMitMExtraHosts)...)
	}
}

var (
	hosts = []string{
		"huggingface.co:443",
	}
)

func mapWithFormat[R any](format string) func(error) (R, error) {
	return func(err error) (R, error) {
		var empty R
		return empty, fmt.Errorf(format, err)
	}
}

func randomSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return mo.TupleToResult(rand.Int(rand.Reader, serialNumberLimit)).MapErr(mapWithFormat[*big.Int]("failed to generate serial number: %w")).MustGet()
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "demodel",
		Short: "Caching, syncing, distributing middleware for models, and datasets.",
		Long: "" +
			"Demodel\n" +
			"\n" +
			"Caching, syncing, distributing middleware for models, and datasets.\n" +
			"\n" +
			"Repository: https://github.com/moeru-ai/demodel\n" +
			"Author: Moeru AI (https://github.com/moeru-ai).\n" +
			"",
		Run: func(cmd *cobra.Command, args []string) {
			start()
		},
	}

	rootCmd.AddCommand(subCommandStart())
	rootCmd.AddCommand(subCommandInit())
	rootCmd.AddCommand(subCommandExportCA())

	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
