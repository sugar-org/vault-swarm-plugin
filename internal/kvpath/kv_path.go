package kvpath

import (
	"fmt"
	"strings"
)

func BuildMountedKVv2SecretPath(mountPath, customPath, secretName string) string {
	if customPath != "" {
		return fmt.Sprintf("%s/data/%s", mountPath, NormalizeRelativePath(mountPath, customPath))
	}

	return fmt.Sprintf("%s/data/%s", mountPath, secretName)
}

func NormalizeRelativePath(mountPath, path string) string {
	path = strings.TrimPrefix(path, mountPath+"/")
	path = strings.TrimPrefix(path, "data/")
	return path
}

func TrimMountedKVSecretPath(secretPath, mountPath string) string {
	return strings.TrimPrefix(secretPath, mountPath+"/data/")
}
