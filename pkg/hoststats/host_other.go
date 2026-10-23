//go:build !darwin

package hoststats

func readHost() (Raw, error) { return Raw{}, ErrUnsupported }
