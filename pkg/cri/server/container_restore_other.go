//go:build !linux
// +build !linux

package server

import (
	"context"
	"github.com/containerd/containerd/oci"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func (c *criService) updateCgroupPath(ctx context.Context, dumpSpec *oci.Spec, mountPoint string, podConfig *types.PodSandboxConfig, ctrId *string) error {
	return nil
}
