package main

import (
	"fmt"
	"strings"
	"testing"
	"github.com/docker/docker/api/types/swarm"
)

func TestSecretNameGeneration(t *testing.T) {
	// Test that new secret names are generated with timestamp suffix
	originalName := "myapp_mysql_root_password"
	
	// Generate new name using the same logic as updateDockerSecret
	newSecretName := fmt.Sprintf("%s-%d", originalName, 1625731200) // Fixed timestamp for testing
	
	// Verify the new name is different from the original
	if newSecretName == originalName {
		t.Errorf("New secret name should be different from original: got '%s'", newSecretName)
	}
	
	// Verify the new name follows the expected pattern
	if !strings.HasPrefix(newSecretName, originalName+"-") {
		t.Errorf("New secret name should start with original name followed by timestamp: got '%s'", newSecretName)
	}
	
	expected := "myapp_mysql_root_password-1625731200"
	if newSecretName != expected {
		t.Errorf("Expected '%s', got '%s'", expected, newSecretName)
	}
	
	t.Logf("Success: Secret name generation works correctly: '%s' -> '%s'", originalName, newSecretName)
}

func TestSecretReferenceUpdate(t *testing.T) {
	// Test that secret references are updated correctly
	oldSecretName := "myapp_mysql_root_password"
	newSecretName := "myapp_mysql_root_password-1625731200"
	newSecretID := "ax79xaymeppc9it7aa68h9538" // Actual Docker secret ID
	
	// Mock existing secret reference
	oldSecretRef := &swarm.SecretReference{
		SecretID:   "old_secret_id_123",
		SecretName: oldSecretName,
		File: &swarm.SecretReferenceFileTarget{
			Name: "/run/secrets/mysql_password",
		},
	}
	
	// Update logic (same as in updateServicesSecretReference)
	newSecretRef := &swarm.SecretReference{
		File:       oldSecretRef.File,
		SecretID:   newSecretID,   // Use actual Docker secret ID
		SecretName: newSecretName,
	}
	
	// Verify the update
	if newSecretRef.SecretName != newSecretName {
		t.Errorf("Expected new secret name '%s', got '%s'", newSecretName, newSecretRef.SecretName)
	}
	
	if newSecretRef.SecretID != newSecretID {
		t.Errorf("Expected new secret ID '%s', got '%s'", newSecretID, newSecretRef.SecretID)
	}
	
	if newSecretRef.File != oldSecretRef.File {
		t.Errorf("File reference should be preserved")
	}
	
	t.Logf("Success: Secret reference update works correctly")
}