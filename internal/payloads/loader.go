package payloads

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func Load(filePath string) ([]string, error) {

	file, err := os.Open(filePath)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to open payload file %s: %w",
			filePath,
			err,
		)
	}

	defer file.Close()

	var payloads []string

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {

		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#") {
			continue
		}

		payloads = append(payloads, line)
	}

	if err := scanner.Err(); err != nil {

		return nil, fmt.Errorf(
			"error reading payload file %s: %w",
			filePath,
			err,
		)
	}

	return payloads, nil
}

func LoadMultiple(files []string) ([]string, error) {

	var allPayloads []string

	seen := make(map[string]struct{})

	for _, file := range files {

		payloads, err := Load(file)

		if err != nil {
			return nil, err
		}

		for _, payload := range payloads {

			if _, exists := seen[payload]; exists {
				continue
			}

			seen[payload] = struct{}{}

			allPayloads = append(
				allPayloads,
				payload,
			)
		}
	}

	return allPayloads, nil
}

func Count(filePath string) (int, error) {

	payloads, err := Load(filePath)

	if err != nil {
		return 0, err
	}

	return len(payloads), nil
}

func LoadDirectory(dir string) ([]string, error) {

	var files []string

	err := filepath.Walk(
		dir,
		func(
			path string,
			info os.FileInfo,
			err error,
		) error {

			if err != nil {
				return nil
			}

			if info == nil {
				return nil
			}

			if info.IsDir() {
				return nil
			}

			if strings.HasSuffix(
				strings.ToLower(path),
				".txt",
			) {

				files = append(
					files,
					path,
				)
			}

			return nil
		},
	)

	if err != nil {
		return nil, err
	}

	return LoadMultiple(files)
}

func LoadCategory(category string) ([]string, error) {

	category = strings.TrimSpace(category)

	if category == "" {
		return nil,
			fmt.Errorf("empty payload category")
	}

	dir := filepath.Join(
		"payloads",
		category,
	)

	return LoadDirectory(dir)
}