package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/adrg/xdg"
	"github.com/moeru-ai/demodel/pkg/utils"
	"github.com/samber/lo"
	"github.com/samber/mo"
	"github.com/spf13/cobra"
)

var (
	subCommandExportCAFlagVarFor = make([]string, 0)
)

func subCommandExportCA() *cobra.Command {
	command := &cobra.Command{
		Use:   "export-ca",
		Short: "Output the CA certificate in PEM format to target destination, default is stdout.",
		Long:  "Output the CA certificate in PEM format to target destination, default is stdout.",
		RunE: func(cmd *cobra.Command, args []string) error {
			certFilePath := mo.TupleToResult(xdg.DataFile("certificates/demodel-ca.crt")).
				MapErr(mapWithFormat[string]("failed to get data file path for storing certificates: %w")).
				MustGet()

			forDestinations := lo.Uniq(subCommandExportCAFlagVarFor)
			forDestinations = lo.Filter(forDestinations, func(dest string, _ int) bool { return dest != "" })

			if !utils.Exists(certFilePath) {
				return fmt.Errorf("CA certificate file does not exist at '%s', did you forget to start at lease once the 'demodel' server? Or perhaps try 'demodel init'\n", certFilePath)
			}

			certFileContent := mo.
				TupleToResult(os.ReadFile(certFilePath)).
				MapErr(mapWithFormat[[]byte]("failed to read CA certificate file: %w")).
				MustGet()

			if len(forDestinations) == 0 {
				fmt.Fprintln(os.Stdout, string(certFileContent))
				return nil
			}

			for _, forDest := range forDestinations {
				switch forDest {
				case "python-ssl":
					cmd := exec.Command("python", "-c", `
import ssl
import json
paths = ssl.get_default_verify_paths()
result = {
    'cafile': paths.cafile,
    'capath': paths.capath,
    'openssl_cafile_env': paths.openssl_cafile_env,
    'openssl_cafile': paths.openssl_cafile,
    'openssl_capath_env': paths.openssl_capath_env,
    'openssl_capath': paths.openssl_capath
}
print(json.dumps(result))
`)
					out, err := cmd.CombinedOutput()
					if err != nil {
						return fmt.Errorf("failed to get default SSL paths for 'python-ssl': %w", err)
					}

					sslPaths := string(out)

					var paths map[string]string
					if err := json.Unmarshal([]byte(sslPaths), &paths); err != nil {
						return fmt.Errorf("failed to parse SSL paths output: %w", err)
					}

					certDst := mo.TupleToResult(os.OpenFile(filepath.Join(paths["capath"], "demodel-ca.crt"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)).
						MapErr(mapWithFormat[*os.File]("failed to open CA certificate file for 'python-ssl': %w")).
						MustGet()

					defer certDst.Close()

					_ = mo.TupleToResult(certDst.Write(certFileContent)).
						MapErr(mapWithFormat[int]("failed to copy CA certificate file to destination for 'python-ssl': %w")).
						MustGet()
				case "python-certifi":
					cmd := exec.Command("python", "-c", "import certifi; print(certifi.where())")
					out, err := cmd.CombinedOutput()
					if err != nil {
						return fmt.Errorf("failed to get default SSL paths for 'python-certifi': %w", err)
					}

					certifiFilePath := strings.TrimSpace(string(out))
					certifiFile := mo.TupleToResult(os.OpenFile(certifiFilePath, os.O_APPEND|os.O_WRONLY, os.ModeAppend)).
						MapErr(mapWithFormat[*os.File]("failed to open certifi CA certificate file: %w")).
						MustGet()

					defer certifiFile.Close()

					_ = mo.TupleToResult(certifiFile.Write(certFileContent)).
						MapErr(mapWithFormat[int]("failed to write CA certificate file to certifi destination: %w")).
						MustGet()
				default:
					return fmt.Errorf("unknown destination '%s' for export-ca command", forDest)
				}
			}

			return nil
		},
	}

	command.Flags().StringArrayVar(&subCommandExportCAFlagVarFor, "for", subCommandExportCAFlagVarFor, ""+
		"Export the CA certificate automatically for specific preset destinations. \n"+
		"- 'python-ssl' for injecting CA into current 'python' executable for 'ssl' module default reading SSL paths.\n"+
		"- 'python-certifi' for injecting CA into current 'python' executable for 'certifi' module default SSL paths.\n"+
		"")

	return command
}
