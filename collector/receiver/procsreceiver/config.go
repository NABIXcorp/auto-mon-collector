package procsreceiver

import (
	"errors"
	"time"
)

// Config mirrors the settings of the shell helper otel-procs.sh: PROCS_TOP, PROCS_WINDOW and the loop interval.
type Config struct {
	CollectionInterval time.Duration `mapstructure:"collection_interval"`
	// Window between the two snapshots; CPU % is measured over it (100 = one core).
	Window time.Duration `mapstructure:"window"`
	// Top N by CPU and top N by RSS (a process in both lists is sent once, top "cpu,rss").
	Top int `mapstructure:"top"`
	// ProcPath is /proc; changeable for tests only.
	ProcPath string `mapstructure:"proc_path"`
}

func createDefaultConfig() *Config {
	return &Config{CollectionInterval: 60 * time.Second, Window: 15 * time.Second, Top: 10, ProcPath: "/proc"}
}

func (c *Config) Validate() error {
	if c.CollectionInterval <= 0 || c.Window <= 0 {
		return errors.New("collection_interval and window must be > 0")
	}
	if c.Window >= c.CollectionInterval {
		return errors.New("window must be shorter than collection_interval")
	}
	if c.Top < 1 || c.Top > 100 {
		return errors.New("top must be 1..100")
	}
	return nil
}
