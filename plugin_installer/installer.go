package main

import (
	"context"
	"fmt"
	"os"
	"regexp"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/api/types/swarm/runtime"
	dockerclient "github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
)

var (
	log = logrus.New()
)

func main() {
	cli, err := dockerclient.NewEnvClient()
	if err != nil {
		log.Fatalf("Error creating Docker client: %v", err)
	}
	serviceName := "vault-secrets-plugin"
	pluginName := "sanjay7178/vault-secrets-plugin:latest"
	if override, exists := os.LookupEnv("plugin_name"); exists {
		pluginName = override
		re := regexp.MustCompile("^(?:.+/|)([^:$]+)(?::.*|)$")
		serviceName = re.ReplaceAllString(pluginName, "${1}")
	}
	remote := pluginName
	if override, exists := os.LookupEnv("remote"); exists {
		remote = override
	}
	service, err := cli.ServiceCreate(context.Background(), swarm.ServiceSpec{
		Annotations: swarm.Annotations{
			Name: serviceName,
		},
		TaskTemplate: swarm.TaskSpec{
			PluginSpec: &runtime.PluginSpec{
				Name:     pluginName,
				Remote:   remote,
				Disabled: false,
				Privileges: []*runtime.PluginPrivilege{
					{
						Name:        "network",
						Description: "permissions to access a network",
						Value:       []string{"host"},
					},
					{
						Name:        "mount",
						Description: "host path to mount",
						Value:       []string{"/var/run/docker.sock"},
					},
					{
						Name:        "capabilities",
						Description: "list of additional capabilities required",
						Value:       []string{"CAP_SYS_ADMIN"},
					},
				},
				Env: []string{
					"policy-template={{ .ServiceName }},{{ .TaskImage }},{{ ServiceLabel \"com.docker.ucp.access.label\" }}",
					"DOCKER_API_VERSION=1.37",
					"VAULT_ADDR=https://152.53.244.80:8200",
					"VAULT_AUTH_METHOD=approle",
					"VAULT_ROLE_ID=8ff294a6-9d5c-c5bb-b494-bc0bfe02a97e",
					"VAULT_SECRET_ID=aedde801-0616-18a5-a62d-c6d7eb483cff",
					"VAULT_MOUNT_PATH=secret",
					"DOCKER_API_VERSION=1.37",
				},
			},
			Placement: &swarm.Placement{
				Constraints: []string{"node.role == manager"},
			},
			Runtime: swarm.RuntimePlugin,
		},
	}, types.ServiceCreateOptions{})
	if err != nil {
		log.Fatalf("Failed to create plugin service: %v", err)
	}
	fmt.Println(service.ID)
}
