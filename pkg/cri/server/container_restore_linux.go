//go:build linux
// +build linux

package server

import (
	"context"
	"fmt"
	"github.com/checkpoint-restore/go-criu/v7/crit/images/cgroup"
	"github.com/containerd/containerd/oci"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"
	"os"
	"path/filepath"

	"github.com/checkpoint-restore/go-criu/v7/crit"
	"github.com/checkpoint-restore/go-criu/v7/crit/cli"
	//stats_pb "github.com/checkpoint-restore/go-criu/v7/crit/images/stats"
	"github.com/containerd/containerd/log"
)

func (c *criService) updateCgroupPath(ctx context.Context, dumpSpec *oci.Spec, mountPoint string, podConfig *types.PodSandboxConfig, ctrId *string) error {
	if dumpSpec.Linux.CgroupsPath != "" {
		log.G(ctx).Infof("Updating cgroup path in cgroup.img")
		// 原始 cgroup 路径
		cgroupPath := dumpSpec.Linux.CgroupsPath

		// checkpoint 挂载点路径
		checkpointMount := filepath.Join("/", mountPoint, "checkpoint")

		// 当前容器的 cgroup 路径
		currentContainerCgroup := filepath.Join("/", podConfig.Linux.CgroupParent, *ctrId)

		// cgroup.img 文件路径
		cgroupImgPath := filepath.Join(checkpointMount, "cgroup.img")

		// 打开 cgroup.img 文件用于读取和写入
		imgFile, err := os.Open(cgroupImgPath)
		if err != nil {
			log.G(ctx).Errorf("Failed to open cgroup.img for reading: %v", err)
			return fmt.Errorf("failed to open cgroup.img: %w", err)
		}
		defer imgFile.Close()

		// 创建临时文件保存修改后的 cgroup.img
		modifiedImgPath := cgroupImgPath + ".modified"
		modifiedFile, err := os.Create(modifiedImgPath)
		if err != nil {
			log.G(ctx).Errorf("Failed to create modified cgroup.img: %v", err)
			return fmt.Errorf("failed to create modified cgroup.img: %w", err)
		}
		defer modifiedFile.Close()

		// 使用 crit.New 创建 CRIT 服务实例
		critService := crit.New(imgFile, modifiedFile, "", false, false)

		// 获取 cgroup.img 的 entry 类型
		entryType, err := cli.GetEntryTypeFromImg(imgFile)
		if err != nil {
			log.G(ctx).Errorf("Failed to get entry type from cgroup.img: %v", err)
			return fmt.Errorf("failed to get entry type: %w", err)
		}

		// 解码 cgroup.img
		decodedImg, err := critService.Decode(entryType)
		if err != nil {
			log.G(ctx).Errorf("Failed to decode cgroup.img: %v", err)
			return fmt.Errorf("failed to decode cgroup.img: %w", err)
		}

		// 遍历并替换路径
		modified := false
		for _, entry := range decodedImg.Entries {
			cgroupEntry, ok := entry.Message.(*cgroup.CgroupEntry)
			if !ok {
				continue
			}

			// 遍历 Sets
			for _, set := range cgroupEntry.GetSets() {
				for _, ctl := range set.GetCtls() {
					if ctl.GetPath() == cgroupPath {
						log.G(ctx).Infof("Replacing cgroup path in Set: %s -> %s", ctl.GetPath(), currentContainerCgroup)
						ctl.Path = &currentContainerCgroup
						modified = true
					}
				}
			}

			// 遍历 Controllers
			for _, controller := range cgroupEntry.GetControllers() {
				for _, dir := range controller.GetDirs() {
					if dir.GetDirName() == cgroupPath {
						log.G(ctx).Infof("Replacing cgroup path in Controller: %s -> %s", dir.GetDirName(), currentContainerCgroup)
						dir.DirName = &currentContainerCgroup
						modified = true
					}
				}
			}
		}

		// 如果路径被修改，重新编码并保存
		if modified {
			err = critService.Encode(decodedImg)
			if err != nil {
				log.G(ctx).Errorf("Failed to encode modified cgroup.img: %v", err)
				return fmt.Errorf("failed to encode modified cgroup.img: %w", err)
			}

			// 替换原始文件
			err = os.Rename(modifiedImgPath, cgroupImgPath)
			if err != nil {
				log.G(ctx).Errorf("Failed to replace original cgroup.img with modified version: %v", err)
				return fmt.Errorf("failed to replace original cgroup.img: %w", err)
			}
			log.G(ctx).Infof("Successfully updated cgroup path in cgroup.img")
		} else {
			log.G(ctx).Infof("No changes made to cgroup.img")
		}
	}
	return nil
}
