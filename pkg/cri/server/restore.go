package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/containerd/containerd/archive"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/pkg/cri/annotations"
	containerstore "github.com/containerd/containerd/pkg/cri/store/container"
	"github.com/containerd/continuity/fs"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	metadata "github.com/checkpoint-restore/checkpointctl/lib"

	"github.com/opencontainers/runtime-tools/generate"
	"github.com/sirupsen/logrus"
)

// ContainerRestore restores a checkpointed container.
func (c *criService) ContainerRestore(
	ctx context.Context,
	config *metadata.ContainerConfig,
	bundlePath string,
) (string, error) {
	var ctr containerstore.Container
	var err error
	ctr, err = c.containerStore.Get(config.ID)
	if err != nil {
		return "", fmt.Errorf("failed to find container %s: %w", config.ID, err)
	}

	//task, err := ctr.Container.Task(ctx, nil)
	//if err != nil {
	//	log.G(ctx).Errorf("Failed to get task for container %s: %v", ctr.ID, err)
	//	return "", err
	//}
	//status, err := task.Status(ctx)
	//if err != nil {
	//	log.G(ctx).Errorf("Failed to get status for container %s: %v", ctr.ID, err)
	//	return "", err
	//}
	//if status.Status == containerd.Running {
	//	return "", fmt.Errorf("cannot restore running container %s", ctr.Name)
	//}

	// Get config.json
	// This file is generated twice by earlier code. Once in BundlePath() and
	// once in Dir(). This code takes the version from Dir(), modifies it and
	// overwrites both versions (Dir() and BundlePath())
	//service := c.client.SnapshotService(containerd.DefaultSnapshotter)
	//service.Stat()

	//return "", errors.New("not implemented")
	//dir := c.getContainerRootDir(ctr.ID)

	//c.loadImages()
	//todo 挂载镜像，操作checkpoint的镜像文件之后用runc restore
	//get, err := c.client.ContainerService().Get(ctx, task.ID())

	//c.client.SnapshotService().Mounts()
	//c.mountPoint()
	// During checkpointing the container is unmounted. This mounts the container again.
	//mountPoint, err := c.StorageImageServer().GetStore().Mount(ctr.ID, ctrSpec.Config.Linux.MountLabel)

	mountPoint := bundlePath
	//show dir file
	printListFiles(ctx, mountPoint)
	//var ctrSpec *generate.SpecGenerator
	ctrSpec, err := generate.NewFromFile(filepath.Join(mountPoint, "config.json"))
	if err != nil {
		return "", err
	}
	//if err != nil {
	//	log.Debugf(ctx, "Failed to mount container %q: %v", ctr.ID(), err)
	//	return "", err
	//}
	//log.Debugf(ctx, "Container mountpoint %v", mountPoint)
	//log.Debugf(ctx, "Sandbox %v", ctr.Sandbox())
	//log.Debugf(ctx, "Specgen.Config.Annotations[io.kubernetes.cri-o.SandboxID] %v", ctrSpec.Config.Annotations["io.kubernetes.cri-o.SandboxID"])
	//sb, err := c.LookupSandbox(ctr.Sandbox())
	//if err != nil {
	//	return "", err
	//}
	sb, err := c.sandboxStore.Get(ctr.SandboxID)
	if err != nil {
		return "", err
	}
	if ctr.RestoreArchive != "" {
		if ctr.RestoreIsOCIImage {
			log.G(ctx).Infof("Restoring from %v", ctr.RestoreArchive)
			imageMountPoint, err := c.mountTMPPoint(ctr.RestoreArchive, ctx)
			if err != nil {
				return "", err
			}
			log.G(ctx).Infof("Checkpoint image mounted at %v", imageMountPoint)
			defer func() {
				err := c.unMount(imageMountPoint, ctx)
				if err != nil {
					log.G(ctx).Errorf("Failed to unmount checkpoint image: %q", err)
					return
				}
				err = os.RemoveAll(imageMountPoint)
				if err != nil {
					log.G(ctx).Errorf("Failed to remove %q: %v", imageMountPoint, err)
				}
			}()

			copyImageDiff(ctx, imageMountPoint, mountPoint)
		} else {
			//todo
			//if err := crutils.CRImportCheckpointWithoutConfig(ctr.Dir(), ctr.RestoreArchive()); err != nil {
			//	return "", err
			//}
		}

		if err := restoreFileSystemChanges(ctx, mountPoint); err != nil {
			return "", err
		}

		//_, err = os.Stat(filepath.Join(dir, "bind.mounts"))
		//if err == nil {
		//	// If the file does not exist we assume it is an older checkpoint archive
		//	// without this type of file and we just ignore it. Possible failures are
		//	// caught in the next block.
		//	var externalBindMounts []ExternalBindMount
		//	_, err := metadata.ReadJSONFile(&externalBindMounts, dir, "bind.mounts")
		//	if err != nil {
		//		return "", err
		//	}
		//	for _, e := range externalBindMounts {
		//		if func() bool {
		//			for _, m := range ctrSpec.Config.Mounts {
		//				if (m.Destination == e.Destination) && (m.Source != e.Source) {
		//					// If the source differs this means that the external mount
		//					// source has already been fixed up earlier by the restore
		//					// code and no need to deal with it here.
		//					// Good example is the /etc/resolv.conf bind mount is now
		//					// pointing to the new /etc/resolv.conf of the new pod.
		//					return true
		//				}
		//			}
		//			return false
		//		}() {
		//			continue
		//		}
		//		_, err = os.Lstat(e.Source)
		//		if err != nil {
		//			// Even if this looks suspicious it is was CRI-O does during
		//			// container create. For each missing bind mount source CRI-O
		//			// creates a directory. For restore that is problematic as
		//			// CRIU will fail to bind mount a directory on a file.
		//			// Therefore during restore CRI-O does not create a directory
		//			// for each missing bind mount source. We track external bind
		//			// mounts in the checkpoint archive and can now recreate missing
		//			// files or directories.
		//			// This is especially useful if restoring a Kubernetes container
		//			// outside of Kubernetes.
		//			if e.FileType == "directory" {
		//				if err := os.MkdirAll(e.Source, os.FileMode(e.Permissions)); err != nil {
		//					return "", fmt.Errorf(
		//						"failed to recreate directory %q for container %s: %w",
		//						e.Source,
		//						ctr.ID(),
		//						err,
		//					)
		//				}
		//			} else {
		//				if err := os.MkdirAll(filepath.Dir(e.Source), 0o700); err != nil {
		//					return "", err
		//				}
		//				source, err := os.OpenFile(
		//					e.Source,
		//					os.O_RDONLY|os.O_CREATE,
		//					os.FileMode(e.Permissions),
		//				)
		//				if err != nil {
		//					return "", fmt.Errorf(
		//						"failed to recreate file %q for container %s: %w",
		//						e.Source,
		//						ctr.ID(),
		//						err,
		//					)
		//				}
		//				source.Close()
		//			}
		//			log.Debugf(ctx, "Created missing external bind mount %q %q\n", e.FileType, e.Source)
		//		}
		//	}
		//}

		//for _, m := range ctrSpec.Config.Mounts {
		//	// This checks if all bind mount sources exist.
		//	// We cannot create missing bind mount sources automatically
		//	// as the source and destination need to be of the same type.
		//	// CRIU will fail restoring if the external bind mount source
		//	// is a directory but the internal destination is a file.
		//	// As destinations can be in nested bind mounts, which are only
		//	// correctly setup by runc/crun during container restore, we
		//	// cannot figure out the file type of the destination.
		//	// At this point we will fail and tell the user to create
		//	// the missing bind mount source file/directory.
		//
		//	// With the code to create directories or files as necessary
		//	// this should not happen anymore. Still keeping the code
		//	// for backwards compatibility.
		//	if m.Type != bindMount {
		//		continue
		//	}
		//	_, err := os.Lstat(m.Source)
		//	if err != nil {
		//		return "", fmt.Errorf(
		//			"the bind mount source %s is missing. %s",
		//			m.Source,
		//			"Please create the corresponding file or directory",
		//		)
		//	}
		//}
	}

	// We need to adapt the to be restored container to the sandbox created for this container.

	// The container will be restored in another sandbox. Adapt to
	// namespaces of the new sandbox
	for i, n := range ctrSpec.Config.Linux.Namespaces {
		if n.Path == "" {
			// The namespace in the original container did not point to
			// an existing interface. Leave it as it is.
			// CRIU will restore the namespace
			continue
		}
		//for _, np := range sb.NamespacePaths() {
		//	if string(np.Type()) == string(n.Type) {
		path := sb.NetNSPath
		ctrSpec.Config.Linux.Namespaces[i].Path = path
		//break
		//}
		//}
	}

	// Update Sandbox Name
	ctrSpec.AddAnnotation(annotations.SandboxName, sb.Name)
	// Update Sandbox ID
	ctrSpec.AddAnnotation(annotations.SandboxID, ctr.SandboxID)

	//mData := fmt.Sprintf(
	//	"k8s_%s_%s_%s_%s0",
	//	ctr.Name,
	//	sb.Name,
	//	sb.Metadata.Config.Metadata.Namespace,
	//	sb.Metadata.ID,
	//)
	//ctrSpec.AddAnnotation(annotations.Name, mData)

	//ctr.SetSandbox(ctr.Sandbox())

	saveOptions := generate.ExportOptions{}
	if err := ctrSpec.SaveToFile(filepath.Join(mountPoint, "config.json"), saveOptions); err != nil {
		return "", err
	}
	//if err := ctrSpec.SaveToFile(filepath.Join(ctr.BundlePath(), "config.json"), saveOptions); err != nil {
	//	return "", err
	//}

	//c.client.Restore(ctx)
	//
	//if err := c.runtime.RestoreContainer(
	//	ctx,
	//	ctr,
	//	sb.CgroupParent,
	//	sb.MountLabel(),
	//); err != nil {
	//	return "", fmt.Errorf("failed to restore container %s: %w", ctr.ID, err)
	//}

	//if err := c.ContainerStateToDisk(ctx, ctr); err != nil {
	//	log.G(ctx).Warnf("Unable to write containers %s state to disk: %v", ctr.ID, err)
	//}

	//if !opts.Keep {
	// Delete all checkpoint related files. At this point, in theory, all files
	// should exist. Still ignoring errors for now as the container should be
	// restored and running. Not erroring out just because some cleanup operation
	// failed. Starting with the checkpoint directory
	checkPointPath := filepath.Join(mountPoint, metadata.CheckpointDirectory)
	err = os.RemoveAll(checkPointPath)
	if err != nil {
		log.G(ctx).Debugf("Non-fatal: removal of checkpoint directory (%s) failed: %v", checkPointPath, err)
	}
	cleanup := [...]string{
		metadata.RestoreLogFile,
		metadata.DumpLogFile,
		"stats-dump",
		"stats-restore",
		metadata.NetworkStatusFile,
		metadata.RootFsDiffTar,
		metadata.DeletedFilesFile,
	}
	for _, del := range cleanup {
		var file string
		//if del == metadata.RestoreLogFile || del == "stats-restore" {
		//	// Checkpointing uses runc and it is possible to tell runc
		//	// the location of the log file using '--work-path'.
		//	// Restore goes through conmon and conmon does (not yet?)
		//	// expose runc's '--work-path' which means that temporary
		//	// restore files are put into BundlePath().
		//	file = filepath.Join(ctr.BundlePath(), del)
		//} else {
		file = filepath.Join(mountPoint, del)
		//}
		err = os.Remove(file)
		if err != nil {
			log.G(ctx).Debugf("Non-fatal: removal of checkpoint file (%s) failed: %v", file, err)
		}
	}
	//}

	return ctr.ID, nil
}

func copyImageDiff(ctx context.Context, imageMountPoint string, mountPoint string) {
	// Import all checkpoint files except ConfigDumpFile and SpecDumpFile. We
	// generate new container config files to enable to specifying a new
	// container name.
	checkpoint := []string{
		"artifacts",
		metadata.CheckpointDirectory,
		metadata.DevShmCheckpointTar,
		metadata.RootFsDiffTar,
		metadata.DeletedFilesFile,
		metadata.PodOptionsFile,
		metadata.PodDumpFile,
		"stats-dump",
		"bind.mounts",
	}
	printListFiles(ctx, imageMountPoint)
	for _, name := range checkpoint {
		src := filepath.Join(imageMountPoint, name)
		dst := filepath.Join(mountPoint, name)

		if err := fs.CopyDir(dst, src); err != nil {
			logrus.Errorf("Can't import '%s' from checkpoint image", name)
		}
	}
}

func restoreFileSystemChanges(ctx context.Context, mountPoint string) error {
	//dir := c.getContainerRootDir(ctr.ID)
	log.G(ctx).Infof("restoreFileSystemChanges Restoring root file-system changes from %s", mountPoint)
	printListFiles(ctx, mountPoint)
	if err := CRApplyRootFsDiffTar(ctx, mountPoint, mountPoint); err != nil {
		return err
	}

	//if err := CRRemoveDeletedFiles(ctr.ID, dir, mountPoint); err != nil {
	//	return err
	//}
	return nil
}

// CRApplyRootFsDiffTar applies the tar archive found in baseDirectory with the
// root file system changes on top of containerRootDirectory
func CRApplyRootFsDiffTar(ctx context.Context, baseDirectory, containerRootDirectory string) error {
	rootfsDiffPath := filepath.Join(baseDirectory, metadata.RootFsDiffTar)
	// Only do this if a rootfs-diff.tar actually exists
	rootfsDiffFile, err := os.Open(rootfsDiffPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to open root file-system diff file: %w", err)
	}
	defer rootfsDiffFile.Close()
	reader := io.Reader(rootfsDiffFile)

	if _, err := archive.Apply(ctx, containerRootDirectory, reader); err != nil {
		return fmt.Errorf("failed to apply root file-system diff file %s: %w", rootfsDiffPath, err)
	}

	return nil
}

// CRRemoveDeletedFiles loads the list of deleted files and if
// it exists deletes all files listed.
func CRRemoveDeletedFiles(id, baseDirectory, containerRootDirectory string) error {
	deletedFiles, _, err := metadata.ReadContainerCheckpointDeletedFiles(baseDirectory)
	if os.IsNotExist(err) {
		// No files to delete. Just return
		return nil
	}

	if err != nil {
		return fmt.Errorf("failed to read deleted files file: %w", err)
	}

	for _, deleteFile := range deletedFiles {
		// Using RemoveAll as deletedFiles, which is generated from 'podman diff'
		// lists completely deleted directories as a single entry: 'D /root'.
		if err := os.RemoveAll(filepath.Join(containerRootDirectory, deleteFile)); err != nil {
			return fmt.Errorf("failed to delete files from container %s during restore: %w", id, err)
		}
	}

	return nil
}
func printListFiles(ctx context.Context, dir string) {
	files, err := os.ReadDir(dir)
	if err != nil {
		log.G(ctx).Infoln("Error reading directory:", err)
		return
	}

	log.G(ctx).Infoln("Files in directory:", dir)
	for _, file := range files {
		log.G(ctx).Infoln(file.Name())
	}
}

func runInNamespace(pid uint32, fn func() error) error {
	// 打开目标进程的网络命名空间文件
	nsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
	fd, err := unix.Open(nsPath, unix.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open network namespace: %v", err)
	}
	defer unix.Close(fd)

	// 保存当前网络命名空间，以便稍后切回来
	originalNS, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to save original network namespace: %v", err)
	}
	defer unix.Close(originalNS)

	// 切换到指定的网络命名空间
	if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("failed to set network namespace: %v", err)
	}

	// 使用 defer 确保在函数结束后切回原始命名空间
	defer func() {
		if err := unix.Setns(originalNS, unix.CLONE_NEWNET); err != nil {
			fmt.Printf("failed to restore original network namespace: %v\n", err)
		}
	}()

	// 在指定命名空间中执行操作
	return fn()
}

func applyIptablesRules(ctx context.Context, pid uint32, markValue int) error {
	// Define iptables rules as a single line string
	rules := fmt.Sprintf(`*filter
:CRIU - [0:0]
-I INPUT -j CRIU
-I OUTPUT -j CRIU
-A CRIU -m mark --mark 0x%X -j ACCEPT
-A CRIU -j DROP
COMMIT
`, markValue)
	log.G(ctx).Infof("Applying iptables rules: %s", rules)
	return runInNamespace(pid, func() error {
		cmd := exec.Command("sh", "-c", fmt.Sprintf("echo '%s' | iptables-restore", rules))

		// 捕获标准错误输出
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to apply iptables rules: %v, output: %s", err, string(output))
		}
		return nil
	})
}

func removeIptablesRules(ctx context.Context, pid uint32) error {
	// 定义删除 iptables 规则的配置，确保每行以 \n 结束
	rules := `*filter
-D INPUT -j CRIU
-D OUTPUT -j CRIU
-X CRIU
COMMIT
`
	log.G(ctx).Infof("Removing iptables rules: %s", rules)
	return runInNamespace(pid, func() error {
		cmd := exec.Command("sh", "-c", fmt.Sprintf("echo '%s' | iptables-restore", rules))

		// 捕获标准错误输出
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to apply iptables rules: %v, output: %s", err, string(output))
		}
		return nil
	})
}
