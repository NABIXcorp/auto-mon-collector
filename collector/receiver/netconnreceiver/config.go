package netconnreceiver

import (
	"errors"
	"fmt"
	"time"
)

// Config mirrors the settings of the shell helper: NETCONN_PORTS and the loop interval.
type Config struct {
	CollectionInterval time.Duration `mapstructure:"collection_interval"`
	Ports              []int         `mapstructure:"ports"`
	// ProcPath is /proc; changeable for tests only.
	ProcPath string `mapstructure:"proc_path"`
}

func createDefaultConfig() *Config {
	return &Config{CollectionInterval: 30 * time.Second, Ports: []int{1521, 8080, 443}, ProcPath: "/proc"}
}

func (c *Config) Validate() error {
	if c.CollectionInterval <= 0 {
		return errors.New("collection_interval must be > 0")
	}
	if len(c.Ports) == 0 {
		return errors.New("ports must not be empty")
	}
	for _, p := range c.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("port %d out of range", p)
		}
	}
	return nil
}
