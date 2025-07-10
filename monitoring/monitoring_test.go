package monitoring

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewMonitor(t *testing.T) {
	interval := 10 * time.Second
	monitor := NewMonitor(interval)
	
	assert.NotNil(t, monitor)
	assert.Equal(t, interval, monitor.interval)
	assert.NotNil(t, monitor.metrics)
	assert.NotNil(t, monitor.ctx)
	assert.NotNil(t, monitor.cancel)
}

func TestMetricsOperations(t *testing.T) {
	monitor := NewMonitor(5 * time.Second)
	
	// Test initial metrics
	metrics := monitor.GetMetrics()
	assert.Equal(t, int64(0), metrics.SecretRotations)
	assert.Equal(t, int64(0), metrics.SecretRotationErrors)
	
	// Test incrementing counters
	monitor.IncrementSecretRotations()
	monitor.IncrementRotationErrors()
	
	metrics = monitor.GetMetrics()
	assert.Equal(t, int64(1), metrics.SecretRotations)
	assert.Equal(t, int64(1), metrics.SecretRotationErrors)
	
	// Test setting rotation interval
	interval := 30 * time.Second
	monitor.SetRotationInterval(interval)
	
	metrics = monitor.GetMetrics()
	assert.Equal(t, interval, metrics.RotationInterval)
}

func TestTickerHeartbeat(t *testing.T) {
	monitor := NewMonitor(5 * time.Second)
	monitor.SetRotationInterval(10 * time.Second)
	
	// Initially no heartbeat
	assert.True(t, monitor.CheckTickerHealth()) // Should be healthy with no heartbeat yet
	
	// Update heartbeat
	monitor.UpdateTickerHeartbeat()
	assert.True(t, monitor.CheckTickerHealth())
	
	// Test metrics include heartbeat time
	metrics := monitor.GetMetrics()
	assert.False(t, metrics.TickerHeartbeat.IsZero())
}

func TestHealthStatus(t *testing.T) {
	monitor := NewMonitor(5 * time.Second)
	monitor.SetRotationInterval(10 * time.Second)
	
	health := monitor.GetHealthStatus()
	
	assert.Contains(t, health, "healthy")
	assert.Contains(t, health, "uptime_seconds")
	assert.Contains(t, health, "goroutines")
	assert.Contains(t, health, "memory_usage_mb")
	assert.Contains(t, health, "total_rotations")
	assert.Contains(t, health, "rotation_errors")
	assert.Contains(t, health, "error_rate")
	assert.Contains(t, health, "ticker_last_beat")
	assert.Contains(t, health, "ticker_healthy")
	
	// Test error rate calculation
	monitor.IncrementSecretRotations()
	monitor.IncrementSecretRotations()
	monitor.IncrementRotationErrors()
	
	health = monitor.GetHealthStatus()
	errorRate := health["error_rate"].(float64)
	assert.InDelta(t, 33.33, errorRate, 0.1) // 1 error out of 3 total = ~33.33%
}

func TestErrorRateCalculation(t *testing.T) {
	monitor := NewMonitor(5 * time.Second)
	
	// Test with no operations
	assert.Equal(t, 0.0, monitor.calculateErrorRate())
	
	// Test with only successes
	monitor.IncrementSecretRotations()
	monitor.IncrementSecretRotations()
	assert.Equal(t, 0.0, monitor.calculateErrorRate())
	
	// Test with some errors
	monitor.IncrementRotationErrors()
	assert.InDelta(t, 33.33, monitor.calculateErrorRate(), 0.1)
	
	// Test with only errors
	monitor = NewMonitor(5 * time.Second)
	monitor.IncrementRotationErrors()
	monitor.IncrementRotationErrors()
	assert.Equal(t, 100.0, monitor.calculateErrorRate())
}

func TestMonitorStartStop(t *testing.T) {
	monitor := NewMonitor(100 * time.Millisecond)
	
	// Start monitoring
	monitor.Start()
	
	// Give it some time to collect a few metrics
	time.Sleep(250 * time.Millisecond)
	
	// Check that metrics are being collected
	metrics := monitor.GetMetrics()
	assert.True(t, metrics.NumGoroutines > 0)
	assert.True(t, metrics.MemAllocBytes > 0)
	
	// Stop monitoring
	monitor.Stop()
	
	// Monitor should stop gracefully
}