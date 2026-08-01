package frps

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
)

type Config struct {
	Binary string
	SHA256 string
	Config string
}

type Process struct {
	cmd  *exec.Cmd
	done chan error
	mu   sync.Mutex
}

func VerifyBinary(path, expectedSHA256 string) error {
	if path == "" || expectedSHA256 == "" {
		return errors.New("FRPS binary and SHA-256 are required")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actual, strings.TrimSpace(expectedSHA256)) {
		return fmt.Errorf("FRPS binary SHA-256 mismatch: got %s", actual)
	}
	return nil
}

func VerifyConfig(binary, configPath string) error {
	if strings.TrimSpace(binary) == "" || strings.TrimSpace(configPath) == "" {
		return errors.New("FRPS binary and config path are required")
	}
	command := exec.Command(binary, "verify", "-c", configPath)
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 240 {
			message = message[:240]
		}
		return fmt.Errorf("FRPS config verification failed: %s", message)
	}
	return nil
}

func Start(config Config) (*Process, error) {
	if err := VerifyBinary(config.Binary, config.SHA256); err != nil {
		return nil, err
	}
	if config.Config == "" {
		return nil, errors.New("FRPS config path is required")
	}
	if err := VerifyConfig(config.Binary, config.Config); err != nil {
		return nil, err
	}
	cmd := exec.Command(config.Binary, "-c", config.Config)
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	process := &Process{cmd: cmd, done: make(chan error, 1)}
	go func() { process.done <- cmd.Wait() }()
	return process, nil
}

func (p *Process) PID() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd == nil || p.cmd.Process == nil {
		return 0
	}
	return p.cmd.Process.Pid
}

func (p *Process) Stop() error {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	_ = p.cmd.Process.Signal(os.Interrupt)
	select {
	case <-p.done:
		return nil
	default:
		_ = p.cmd.Process.Kill()
		<-p.done
		return nil
	}
}
