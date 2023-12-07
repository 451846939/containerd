package sbserver

import (
	"fmt"
	metadata "github.com/checkpoint-restore/checkpointctl/lib"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/leases"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/pkg/cri/annotations"
	"github.com/containerd/containerd/platforms"
	"github.com/opencontainers/image-spec/identity"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"
	"os"
	"time"
)

func (s *criService) checkIfCheckpointImage(ctx context.Context, input string) (bool, error) {
	if _, err := os.Stat(input); err == nil {
		log.G(ctx).Errorf("Image %q is a local file, not a checkpoint", input)
		return false, nil
	}
	imageStatusRespone, err := s.ImageStatus(
		ctx,
		&types.ImageStatusRequest{
			Image: &types.ImageSpec{
				Image: input,
			},
		},
	)
	if err != nil {
		log.G(ctx).Errorf("Failed to get image status of %q: %v", input, err)
		return false, err
	}
	log.G(ctx).Infof("Found checkpoint of container %v in %v", imageStatusRespone.Image, input)
	if imageStatusRespone == nil ||
		imageStatusRespone.Image == nil ||
		imageStatusRespone.Image.Spec == nil ||
		imageStatusRespone.Image.Spec.Annotations == nil {
		log.G(ctx).Infof("No checkpoint found in %v", input)
		return false, nil
	}

	ann, ok := imageStatusRespone.Image.Spec.Annotations[annotations.CheckpointAnnotationName]
	if !ok {
		log.G(ctx).Infof("No checkpoint found CheckpointAnnotationName in %v", input)
		return false, nil
	}

	logrus.Debugf("Found checkpoint of container %v in %v", ann, input)

	return true, nil
}
func (c *criService) CRImportCheckpoint(
	ctx context.Context,
	createConfig *types.ContainerConfig,
	sbID string,
	ctrId *string,
) (sandboxConfig *types.PodSandboxConfig, containerConfig *types.ContainerConfig, retErr error) {
	mountPoint, err := os.MkdirTemp("", "checkpoint")
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		err := os.RemoveAll(mountPoint)
		if err != nil {
			log.G(ctx).Errorf("Failed to remove %q: %v", mountPoint, retErr)
		}
	}()

	input := createConfig.Image.Image
	createMounts := createConfig.Mounts
	createAnnotations := createConfig.Annotations
	createLabels := createConfig.Labels
	checkpointIsOCIImage, err := c.checkIfCheckpointImage(ctx, input)
	if err != nil {
		return nil, nil, err
	}
	createAnnotations[annotations.CheckpointAnnotationName] = "checkpoint"
	log.G(ctx).Infof("checkpointIsOCIImage %v", checkpointIsOCIImage)
	if checkpointIsOCIImage {
		log.G(ctx).Debugf("Restoring from image \n", input)
		//c.client.ImageService()
		//mounts, err = c.Prepare(ctx, target, chainID)
		//mount.All()
		//mounts[0].HostPath
		//image, retErr := c.localResolve(input)
		//if retErr != nil {
		//	return "", retErr
		//}
		//containerdImage, err := c.toContainerdImage(ctx, image)
		//if err != nil {
		//	return "", fmt.Errorf("failed to get image from containerd %q: %w", image.ID, err)
		//}
		//if err := mount.All(mounts, target); err != nil {
		//	if err := c.Remove(ctx, target); err != nil && !errdefs.IsNotFound(err) {
		//		fmt.Fprintln(context.App.ErrWriter, "Error cleaning up snapshot after mount error:", err)
		//	}
		//	return err
		//}
		//containerdImage.Unpack(ctx, c.Snapshotter)
		////c.loadImages(arr)
		//// Pull image to ensure the image exists
		//resp, err := c.PullImage(ctx, &runtime.PullImageRequest{Image: &runtime.ImageSpec{Image: ref}, SandboxConfig: config})
		//if err != nil {
		//	return nil, fmt.Errorf("failed to pull image %q: %w", ref, err)
		//}
		//imageID := resp.GetImageRef()
		//newImage, err := c.imageStore.Get(imageID)
		//if err != nil {
		//	// It'c still possible that someone removed the image right after it is pulled.
		//	return nil, fmt.Errorf("failed to get image %q after pulling: %w", imageID, err)
		//}
		//mountPoint, err = c.checkpointImage(ctx, createConfig, sbID, sandboxUID)
		//if err != nil {
		//	return "", err
		//}
		c.mountPoint(input, mountPoint, ctx)
		defer c.unMount(mountPoint, ctx)
	}

	// Load spec.dump from temporary directory
	dumpSpec := new(oci.Spec)
	if _, err := metadata.ReadJSONFile(dumpSpec, mountPoint, metadata.SpecDumpFile); err != nil {
		return nil, nil, fmt.Errorf("failed to read %q: %w", metadata.SpecDumpFile, err)
	}

	// Load config.dump from temporary directory
	config := new(metadata.ContainerConfig)
	if _, err := metadata.ReadJSONFile(config, mountPoint, metadata.ConfigDumpFile); err != nil {
		return nil, nil, fmt.Errorf("failed to read %q: %w", metadata.ConfigDumpFile, err)
	}

	if sbID == "" {
		// restore into previous sandbox
		sbID = dumpSpec.Annotations[annotations.SandboxID]
		*ctrId = config.ID
	}

	ctrMetadata := types.ContainerMetadata{}
	//originalAnnotations := make(map[string]string)
	//originalLabels := make(map[string]string)
	ctrMetadata.Name = dumpSpec.Annotations[annotations.ContainerName]
	if createConfig.Metadata != nil && createConfig.Metadata.Name != "" {
		ctrMetadata.Name = createConfig.Metadata.Name
	}
	//if err := json.Unmarshal([]byte(dumpSpec.Annotations[annotations.PodAnnotations]), &originalAnnotations); err != nil {
	//	return "", fmt.Errorf("failed to read %q: %w", annotations.PodAnnotations, err)
	//}

	// update container config

	// Newer checkpoints archives have RootfsImageRef set
	// and using it for the restore is more correct.
	// For the Kubernetes use case the output of 'crictl ps'
	// contains for the original container under 'IMAGE' something
	// like 'registry/path/container@sha256:123444444...'.
	// The restored container was, however, only displaying something
	// like 'registry/path/container'.
	// This had two problems, first, the output from the restored
	// container was different, but the bigger problem was, that
	// might pull the wrong image from the registry.
	// If the container in the registry was updated (new latest tag)
	// all of a sudden the wrong base image would be downloaded.
	rootFSImage := config.RootfsImageName
	if config.RootfsImageRef != "" {
		//id, err := storage.ParseStorageImageIDFromOutOfProcessData(config.RootfsImageRef)
		//if err != nil {
		//	return "", fmt.Errorf("invalid RootfsImageRef %q: %w", config.RootfsImageRef, err)
		//}
		//// This is not quite out-of-process consumption, but types.containerConfig is at least
		//// a cross-process API, and this value is correct in that API.
		//rootFSImage = id.IDStringForOutOfProcessConsumptionOnly()
	}
	containerConfig = &types.ContainerConfig{
		Metadata: &types.ContainerMetadata{
			Name:    ctrMetadata.Name,
			Attempt: createConfig.Metadata.Attempt,
		},
		Image: &types.ImageSpec{
			Image: rootFSImage,
		},
		Linux: &types.LinuxContainerConfig{
			Resources:       &types.LinuxContainerResources{},
			SecurityContext: &types.LinuxContainerSecurityContext{},
		},
		Annotations: createAnnotations,
		Labels:      createLabels,
	}

	if createConfig.Linux.Resources != nil {
		containerConfig.Linux.Resources = createConfig.Linux.Resources
	}
	if createConfig.Linux.SecurityContext != nil {
		containerConfig.Linux.SecurityContext = createConfig.Linux.SecurityContext
	}

	if dumpSpec.Linux != nil {
		if dumpSpec.Linux.MaskedPaths != nil {
			containerConfig.Linux.SecurityContext.MaskedPaths = dumpSpec.Linux.MaskedPaths
		}

		if dumpSpec.Linux.ReadonlyPaths != nil {
			containerConfig.Linux.SecurityContext.ReadonlyPaths = dumpSpec.Linux.ReadonlyPaths
		}
	}

	ignoreMounts := map[string]bool{
		"/proc":              true,
		"/dev":               true,
		"/dev/pts":           true,
		"/dev/mqueue":        true,
		"/sys":               true,
		"/sys/fs/cgroup":     true,
		"/dev/shm":           true,
		"/etc/resolv.conf":   true,
		"/etc/hostname":      true,
		"/run/secrets":       true,
		"/run/.containerenv": true,
	}

	for _, m := range dumpSpec.Mounts {
		// Following mounts are ignored as they might point to the
		// wrong location and if ignored the mounts will correctly
		// be setup to point to the new location.
		if ignoreMounts[m.Destination] {
			continue
		}
		mount := &types.Mount{
			ContainerPath: m.Destination,
			HostPath:      m.Source,
		}

		for _, createMount := range createMounts {
			if createMount.ContainerPath == m.Destination {
				mount.HostPath = createMount.HostPath
			}
		}

		for _, opt := range m.Options {
			switch opt {
			case "ro":
				mount.Readonly = true
			case "rprivate":
				mount.Propagation = types.MountPropagation_PROPAGATION_PRIVATE
			case "rshared":
				mount.Propagation = types.MountPropagation_PROPAGATION_BIDIRECTIONAL
			case "rslaved":
				mount.Propagation = types.MountPropagation_PROPAGATION_HOST_TO_CONTAINER
			}
		}

		log.G(ctx).Debugf("Adding mounts %#v", mount)
		containerConfig.Mounts = append(containerConfig.Mounts, mount)

	}

	sb, retErr := c.sandboxStore.Get(sbID)
	if retErr != nil {
		return nil, nil, retErr
	}

	sandboxConfig = &types.PodSandboxConfig{
		Metadata: &types.PodSandboxMetadata{
			Name:      sb.Config.Metadata.Name,
			Uid:       sb.Config.Metadata.Uid,
			Namespace: sb.Config.Metadata.Namespace,
			Attempt:   sb.Config.Metadata.Attempt,
		},
		Linux: &types.LinuxPodSandboxConfig{},
	}
	return sandboxConfig, containerConfig, nil
}
func (c *criService) mountTMPPoint(ref string, ctx context.Context) (string string, retErr error) {
	mountPoint, err := os.MkdirTemp("", "checkpoint")
	if err != nil {
		return "", err
	}
	err = c.mountPoint(ref, mountPoint, ctx)
	if err != nil {
		return "", err
	}
	return mountPoint, nil
}
func (c *criService) mountPoint(ref string, target string, ctx context.Context) (retErr error) {
	//snapshotter := context.String("snapshotter")
	snapshotter := containerd.DefaultSnapshotter
	//if snapshotter == "" {
	//	snapshotter = containerd.DefaultSnapshotter
	//}

	ctx, done, err := c.client.WithLease(ctx,
		leases.WithID(target),
		leases.WithExpiration(24*time.Hour),
		leases.WithLabels(map[string]string{
			"containerd.io/gc.ref.snapshot." + snapshotter: target,
		}),
	)
	if err != nil && !errdefs.IsAlreadyExists(err) {
		return err
	}

	defer func() {
		if retErr != nil && done != nil {
			done(ctx)
		}
	}()

	//ps := context.String("platform")
	ps := ""
	p, err := platforms.Parse(ps)
	if err != nil {
		return fmt.Errorf("unable to parse platform %c: %w", ps, err)
	}

	img, err := c.client.ImageService().Get(ctx, ref)
	if err != nil {
		return err
	}

	i := containerd.NewImageWithPlatform(c.client, img, platforms.Only(p))
	if err := i.Unpack(ctx, snapshotter); err != nil {
		return fmt.Errorf("error unpacking image: %w", err)
	}

	diffIDs, err := i.RootFS(ctx)
	if err != nil {
		return err
	}
	chainID := identity.ChainID(diffIDs).String()
	fmt.Println(chainID)

	s := c.client.SnapshotService(snapshotter)

	var mounts []mount.Mount
	//if context.Bool("rw") {
	mounts, err = s.Prepare(ctx, target, chainID)
	//} else {
	//	mounts, err = s.View(ctx, target, chainID)
	//}
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			mounts, err = s.Mounts(ctx, target)
		}
		if err != nil {
			return err
		}
	}

	if err := mount.All(mounts, target); err != nil {
		if err := s.Remove(ctx, target); err != nil && !errdefs.IsNotFound(err) {
			log.G(ctx).Errorf("Error cleaning up snapshot after mount error: %v", err)
		}
		return err
	}
	return nil
}

func (c criService) unMount(target string, ctx context.Context) error {
	if err := mount.UnmountAll(target, 0); err != nil {
		return err
	}

	snapshotter := ""
	s := c.client.SnapshotService(snapshotter)
	if err := c.client.LeasesService().Delete(ctx, leases.Lease{ID: target}); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("error deleting lease: %w", err)
	}
	if err := s.Remove(ctx, target); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("error removing snapshot: %w", err)
	}
	return nil
}
