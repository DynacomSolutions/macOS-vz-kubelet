package buildutil

import (
	"encoding/json"
	"errors"
	"regexp"
)

var wholeDisk = regexp.MustCompile(`^/dev/disk[0-9]+$`)

type entities struct {
	SystemEntities []struct {
		DevEntry string `json:"dev-entry"`
	} `json:"system-entities"`
}

func wholeDiskOf(e entities) string {
	for _, se := range e.SystemEntities {
		if wholeDisk.MatchString(se.DevEntry) {
			return se.DevEntry
		}
	}
	return ""
}

// ParseAttach returns the whole-disk node (/dev/diskN) from `hdiutil attach -plist` output
// converted to JSON.
func ParseAttach(js []byte) (string, error) {
	var e entities
	if err := json.Unmarshal(js, &e); err != nil {
		return "", err
	}
	if d := wholeDiskOf(e); d != "" {
		return d, nil
	}
	return "", errors.New("hdiutil attach reported no device")
}

// FindImageDevice returns the whole-disk node of the attached image whose image-path is one of
// paths, from `hdiutil info -plist` converted to JSON; "" when it is not attached.
func FindImageDevice(js []byte, paths ...string) (string, error) {
	var info struct {
		Images []struct {
			ImagePath string `json:"image-path"`
			entities
		} `json:"images"`
	}
	if err := json.Unmarshal(js, &info); err != nil {
		return "", err
	}
	for _, img := range info.Images {
		for _, p := range paths {
			if img.ImagePath == p {
				return wholeDiskOf(img.entities), nil
			}
		}
	}
	return "", nil
}
