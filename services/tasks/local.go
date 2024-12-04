/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package tasks

import (
	"bytes"
	"context"
	"fmt"
	"github.com/checkpoint-restore/go-criu/v7/crit"
	"github.com/checkpoint-restore/go-criu/v7/crit/cli"
	"github.com/checkpoint-restore/go-criu/v7/crit/images/cgroup"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/oci"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	crmetadata "github.com/checkpoint-restore/checkpointctl/lib"
	api "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/archive"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/filters"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/metadata"
	"github.com/containerd/containerd/mount"
	"github.com/containerd/containerd/pkg/timeout"
	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/protobuf"
	"github.com/containerd/containerd/protobuf/proto"
	ptypes "github.com/containerd/containerd/protobuf/types"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/containerd/runtime/linux/runctypes"
	"github.com/containerd/containerd/runtime/v2/runc/options"
	"github.com/containerd/containerd/services"
	"github.com/containerd/typeurl"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	_     = (api.TasksClient)(&local{})
	empty = &ptypes.Empty{}
)

const (
	stateTimeout = "io.containerd.timeout.task.state"
)

// Config for the tasks service plugin
type Config struct {
	// BlockIOConfigFile specifies the path to blockio configuration file
	BlockIOConfigFile string `toml:"blockio_config_file" json:"blockioConfigFile"`
	// RdtConfigFile specifies the path to RDT configuration file
	RdtConfigFile string `toml:"rdt_config_file" json:"rdtConfigFile"`
}

func init() {
	plugin.Register(&plugin.Registration{
		Type:     plugin.ServicePlugin,
		ID:       services.TasksService,
		Requires: tasksServiceRequires,
		Config:   &Config{},
		InitFn:   initFunc,
	})

	timeout.Set(stateTimeout, 2*time.Second)
}

func initFunc(ic *plugin.InitContext) (interface{}, error) {
	config := ic.Config.(*Config)
	runtimes, err := loadV1Runtimes(ic)
	if err != nil {
		return nil, err
	}

	v2r, err := ic.GetByID(plugin.RuntimePluginV2, "task")
	if err != nil {
		return nil, err
	}

	m, err := ic.Get(plugin.MetadataPlugin)
	if err != nil {
		return nil, err
	}

	ep, err := ic.Get(plugin.EventPlugin)
	if err != nil {
		return nil, err
	}

	monitor, err := ic.Get(plugin.TaskMonitorPlugin)
	if err != nil {
		if !errdefs.IsNotFound(err) {
			return nil, err
		}
		monitor = runtime.NewNoopMonitor()
	}

	db := m.(*metadata.DB)
	l := &local{
		runtimes:   runtimes,
		containers: metadata.NewContainerStore(db),
		store:      db.ContentStore(),
		publisher:  ep.(events.Publisher),
		monitor:    monitor.(runtime.TaskMonitor),
		v2Runtime:  v2r.(runtime.PlatformRuntime),
	}
	for _, r := range runtimes {
		tasks, err := r.Tasks(ic.Context, true)
		if err != nil {
			return nil, err
		}
		for _, t := range tasks {
			l.monitor.Monitor(t, nil)
		}
	}
	v2Tasks, err := l.v2Runtime.Tasks(ic.Context, true)
	if err != nil {
		return nil, err
	}
	for _, t := range v2Tasks {
		l.monitor.Monitor(t, nil)
	}

	if err := initBlockIO(config.BlockIOConfigFile); err != nil {
		log.G(ic.Context).WithError(err).Errorf("blockio initialization failed")
	}
	if err := initRdt(config.RdtConfigFile); err != nil {
		log.G(ic.Context).WithError(err).Errorf("RDT initialization failed")
	}

	return l, nil
}

type local struct {
	runtimes   map[string]runtime.PlatformRuntime
	containers containers.Store
	store      content.Store
	publisher  events.Publisher

	monitor   runtime.TaskMonitor
	v2Runtime runtime.PlatformRuntime
}

func (l *local) Create(ctx context.Context, r *api.CreateTaskRequest, _ ...grpc.CallOption) (*api.CreateTaskResponse, error) {
	container, err := l.getContainer(ctx, r.ContainerID)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	//todo 直接把oci镜像解压挂载到一个临时目录然后传进来再进行别的操作
	checkpointPath, err := getRestorePath(container.Runtime.Name, r.Options)
	if err != nil {
		return nil, err
	}
	// jump get checkpointPath from checkpoint image
	if checkpointPath == "" && r.Checkpoint != nil {
		checkpointPath, err = os.MkdirTemp(os.Getenv("XDG_RUNTIME_DIR"), "ctrd-checkpoint")
		if err != nil {
			return nil, err
		}
		if r.Checkpoint.MediaType != images.MediaTypeContainerd1Checkpoint {
			return nil, fmt.Errorf("unsupported checkpoint type %q", r.Checkpoint.MediaType)
		}
		reader, err := l.store.ReaderAt(ctx, ocispec.Descriptor{
			MediaType:   r.Checkpoint.MediaType,
			Digest:      digest.Digest(r.Checkpoint.Digest),
			Size:        r.Checkpoint.Size,
			Annotations: r.Checkpoint.Annotations,
		})
		if err != nil {
			return nil, err
		}
		_, err = archive.Apply(ctx, checkpointPath, content.NewReader(reader))
		reader.Close()
		if err != nil {
			return nil, err
		}
	}
	opts := runtime.CreateOpts{
		Spec: container.Spec,
		IO: runtime.IO{
			Stdin:    r.Stdin,
			Stdout:   r.Stdout,
			Stderr:   r.Stderr,
			Terminal: r.Terminal,
		},
		Checkpoint:     checkpointPath,
		Runtime:        container.Runtime.Name,
		RuntimeOptions: container.Runtime.Options,
		TaskOptions:    r.Options,
		SandboxID:      container.SandboxID,
	}
	if r.RuntimePath != "" {
		opts.Runtime = r.RuntimePath
	}
	for _, m := range r.Rootfs {
		opts.Rootfs = append(opts.Rootfs, mount.Mount{
			Type:    m.Type,
			Source:  m.Source,
			Target:  m.Target,
			Options: m.Options,
		})
	}
	if checkpointPath != "" && r.Checkpoint == nil {
		// fixme 这里暂时使用写死的测试流程
		opts.Checkpoint = checkpointPath + "/checkpoint"
	}
	if strings.HasPrefix(container.Runtime.Name, "io.containerd.runtime.v1.") {
		log.G(ctx).Warn("runtime v1 is deprecated since containerd v1.4, consider using runtime v2")
	} else if container.Runtime.Name == plugin.RuntimeRuncV1 {
		log.G(ctx).Warnf("%q is deprecated since containerd v1.4, consider using %q", plugin.RuntimeRuncV1, plugin.RuntimeRuncV2)
	}
	rtime, err := l.getRuntime(container.Runtime.Name)
	if err != nil {
		return nil, err
	}
	_, err = rtime.Get(ctx, r.ContainerID)
	if err != nil && !errdefs.IsNotFound(err) {
		return nil, errdefs.ToGRPC(err)
	}
	if err == nil {
		return nil, errdefs.ToGRPC(fmt.Errorf("task %s: %w", r.ContainerID, errdefs.ErrAlreadyExists))
	}
	c, err := rtime.Create(ctx, r.ContainerID, opts)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	bundlePath := c.BundlePath(ctx)
	//todo 修改config.json 里面的nspath 符合目前的sandbox否则无法恢复
	if checkpointPath != "" && r.Checkpoint == nil {
		log.G(ctx).Infof("CopyImageDiff befor checkpointPath is %s", checkpointPath)
		containerd.PrintListFiles(ctx, bundlePath)
		containerd.CopyImageDiff(ctx, checkpointPath, bundlePath)
		log.G(ctx).Infof("CopyImageDiff after checkpointPath is %s", checkpointPath)
		containerd.PrintListFiles(ctx, bundlePath)

		err = UpdateCgroupPath(ctx, checkpointPath, bundlePath)

		if err != nil {
			log.G(ctx).Errorf("UpdateCgroupPath failed %s", err)
			return nil, err
		}
		err = containerd.RestoreFileSystemChanges(ctx, bundlePath)
		if err != nil {
			log.G(ctx).Errorf("RestoreFileSystemChanges failed %s", err)
			return nil, err
		}
	}

	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	labels := map[string]string{"runtime": container.Runtime.Name}
	if err := l.monitor.Monitor(c, labels); err != nil {
		return nil, fmt.Errorf("monitor task: %w", err)
	}
	pid, err := c.PID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get task pid: %w", err)
	}
	return &api.CreateTaskResponse{
		ContainerID: r.ContainerID,
		Pid:         pid,
	}, nil
}
func UpdateCgroupPath(ctx context.Context, mountPoint string, bundlePath string) error {
	log.G(ctx).Infof("Updating cgroup path in cgroup.img")

	// checkpoint 挂载点路径
	checkpointMount := filepath.Join("/", mountPoint, "checkpoint")
	//checkpointMount := checkpointPath
	dumpSpec := new(oci.Spec)
	if _, err := crmetadata.ReadJSONFile(dumpSpec, mountPoint, crmetadata.SpecDumpFile); err != nil {
		return fmt.Errorf("failed to read %q: %w", "checkpointPath config.json", err)
	}

	cgroupPath := dumpSpec.Linux.CgroupsPath
	// 当前容器的 cgroup 路径
	config := new(oci.Spec)
	if _, err := crmetadata.ReadJSONFile(config, bundlePath, "config.json"); err != nil {
		return fmt.Errorf("failed to read %q: %w", "bundlePath config.json", err)
	}

	currentContainerCgroup := config.Linux.CgroupsPath

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
					log.G(ctx).Infof("Replacing %s cgroup path in Set: %s -> %s", ctl.GetName(), ctl.GetPath(), currentContainerCgroup)
					ctl.Path = &currentContainerCgroup
					modified = true
				}
			}
		}

		// 遍历 Controllers 并修改路径
		for _, controller := range cgroupEntry.GetControllers() {
			for _, dir := range controller.GetDirs() {
				// 修改 dir_name
				log.G(ctx).Infof("Replacing %s cgroup path in Controller.Dir: %s -> %s", controller.GetCnames(), dir.GetDirName(), currentContainerCgroup)
				if dir.GetDirName() == cgroupPath {
					log.G(ctx).Infof("Replacing %s cgroup path in Controller.Dir: %s -> %s ok", controller.GetCnames(), dir.GetDirName(), currentContainerCgroup)
					dir.DirName = &currentContainerCgroup
					modified = true
				}

				// 遍历并修改 children 中的路径
				for _, child := range dir.GetChildren() {
					if child.GetDirName() == cgroupPath {
						log.G(ctx).Infof("Replacing cgroup path in Controller.Dir.Children: %s -> %s", child.GetDirName(), currentContainerCgroup)
						child.DirName = &currentContainerCgroup
						modified = true
					}
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

		// 确保目标目录存在
		targetCheckpointDir := filepath.Join("/", bundlePath, "checkpoint")
		if err := os.MkdirAll(targetCheckpointDir, 0755); err != nil {
			log.G(ctx).Errorf("Failed to create target checkpoint directory: %v", err)
			return fmt.Errorf("failed to create target checkpoint directory: %w", err)
		}

		// 将修改后的文件移动到指定目录中
		targetCgroupImgPath := filepath.Join(targetCheckpointDir, "cgroup.img")
		log.G(ctx).Infof("Moving modified cgroup.img to %s", targetCgroupImgPath)
		err = os.Rename(modifiedImgPath, targetCgroupImgPath)
		if err != nil {
			log.G(ctx).Errorf("Failed to replace original cgroup.img with modified version: %v", err)
			return fmt.Errorf("failed to replace original cgroup.img: %w", err)
		}
		log.G(ctx).Infof("Successfully updated cgroup path in cgroup.img at %s", targetCgroupImgPath)
	} else {
		log.G(ctx).Infof("No changes made to cgroup.img")
	}
	return nil
}

func (l *local) Start(ctx context.Context, r *api.StartRequest, _ ...grpc.CallOption) (*api.StartResponse, error) {
	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	p := runtime.Process(t)
	if r.ExecID != "" {
		if p, err = t.Process(ctx, r.ExecID); err != nil {
			return nil, errdefs.ToGRPC(err)
		}
	}
	log.G(ctx).Infof("starting process id %s p %v", p.ID(), p)
	if err := p.Start(ctx); err != nil {
		log.G(ctx).WithError(err).Errorf("start process %s", p.ID())
		return nil, errdefs.ToGRPC(err)
	}
	log.G(ctx).Infof("started process id %s p %v", p.ID(), p)
	state, err := p.State(ctx)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return &api.StartResponse{
		Pid: state.Pid,
	}, nil
}

func (l *local) Delete(ctx context.Context, r *api.DeleteTaskRequest, _ ...grpc.CallOption) (*api.DeleteResponse, error) {
	container, err := l.getContainer(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}

	// Find runtime manager
	rtime, err := l.getRuntime(container.Runtime.Name)
	if err != nil {
		return nil, err
	}

	// Get task object
	t, err := rtime.Get(ctx, container.ID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "task %v not found", container.ID)
	}

	if err := l.monitor.Stop(t); err != nil {
		return nil, err
	}

	exit, err := rtime.Delete(ctx, r.ContainerID)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}

	return &api.DeleteResponse{
		ExitStatus: exit.Status,
		ExitedAt:   protobuf.ToTimestamp(exit.Timestamp),
		Pid:        exit.Pid,
	}, nil
}

func (l *local) DeleteProcess(ctx context.Context, r *api.DeleteProcessRequest, _ ...grpc.CallOption) (*api.DeleteResponse, error) {
	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	process, err := t.Process(ctx, r.ExecID)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	exit, err := process.Delete(ctx)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return &api.DeleteResponse{
		ID:         r.ExecID,
		ExitStatus: exit.Status,
		ExitedAt:   protobuf.ToTimestamp(exit.Timestamp),
		Pid:        exit.Pid,
	}, nil
}

func getProcessState(ctx context.Context, p runtime.Process) (*task.Process, error) {
	ctx, cancel := timeout.WithContext(ctx, stateTimeout)
	defer cancel()

	state, err := p.State(ctx)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil, err
		}
		log.G(ctx).WithError(err).Errorf("get state for %s", p.ID())
	}
	status := task.Status_UNKNOWN
	switch state.Status {
	case runtime.CreatedStatus:
		status = task.Status_CREATED
	case runtime.RunningStatus:
		status = task.Status_RUNNING
	case runtime.StoppedStatus:
		status = task.Status_STOPPED
	case runtime.PausedStatus:
		status = task.Status_PAUSED
	case runtime.PausingStatus:
		status = task.Status_PAUSING
	default:
		log.G(ctx).WithField("status", state.Status).Warn("unknown status")
	}
	return &task.Process{
		ID:         p.ID(),
		Pid:        state.Pid,
		Status:     status,
		Stdin:      state.Stdin,
		Stdout:     state.Stdout,
		Stderr:     state.Stderr,
		Terminal:   state.Terminal,
		ExitStatus: state.ExitStatus,
		ExitedAt:   protobuf.ToTimestamp(state.ExitedAt),
	}, nil
}

func (l *local) Get(ctx context.Context, r *api.GetRequest, _ ...grpc.CallOption) (*api.GetResponse, error) {
	task, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	p := runtime.Process(task)
	if r.ExecID != "" {
		if p, err = task.Process(ctx, r.ExecID); err != nil {
			return nil, errdefs.ToGRPC(err)
		}
	}
	t, err := getProcessState(ctx, p)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return &api.GetResponse{
		Process: t,
	}, nil
}

func (l *local) List(ctx context.Context, r *api.ListTasksRequest, _ ...grpc.CallOption) (*api.ListTasksResponse, error) {
	resp := &api.ListTasksResponse{}
	for _, r := range l.allRuntimes() {
		tasks, err := r.Tasks(ctx, false)
		if err != nil {
			return nil, errdefs.ToGRPC(err)
		}
		addTasks(ctx, resp, tasks)
	}
	return resp, nil
}

func addTasks(ctx context.Context, r *api.ListTasksResponse, tasks []runtime.Task) {
	for _, t := range tasks {
		tt, err := getProcessState(ctx, t)
		if err != nil {
			if !errdefs.IsNotFound(err) { // handle race with deletion
				log.G(ctx).WithError(err).WithField("id", t.ID()).Error("converting task to protobuf")
			}
			continue
		}
		r.Tasks = append(r.Tasks, tt)
	}
}

func (l *local) Pause(ctx context.Context, r *api.PauseTaskRequest, _ ...grpc.CallOption) (*ptypes.Empty, error) {
	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	err = t.Pause(ctx)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return empty, nil
}

func (l *local) Resume(ctx context.Context, r *api.ResumeTaskRequest, _ ...grpc.CallOption) (*ptypes.Empty, error) {
	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	err = t.Resume(ctx)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return empty, nil
}

func (l *local) Kill(ctx context.Context, r *api.KillRequest, _ ...grpc.CallOption) (*ptypes.Empty, error) {
	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	p := runtime.Process(t)
	if r.ExecID != "" {
		if p, err = t.Process(ctx, r.ExecID); err != nil {
			return nil, errdefs.ToGRPC(err)
		}
	}
	if err := p.Kill(ctx, r.Signal, r.All); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return empty, nil
}

func (l *local) ListPids(ctx context.Context, r *api.ListPidsRequest, _ ...grpc.CallOption) (*api.ListPidsResponse, error) {
	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	processList, err := t.Pids(ctx)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	var processes []*task.ProcessInfo
	for _, p := range processList {
		pInfo := task.ProcessInfo{
			Pid: p.Pid,
		}
		if p.Info != nil {
			a, err := protobuf.MarshalAnyToProto(p.Info)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal process %d info: %w", p.Pid, err)
			}
			pInfo.Info = a
		}
		processes = append(processes, &pInfo)
	}
	return &api.ListPidsResponse{
		Processes: processes,
	}, nil
}

func (l *local) Exec(ctx context.Context, r *api.ExecProcessRequest, _ ...grpc.CallOption) (*ptypes.Empty, error) {
	if r.ExecID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "exec id cannot be empty")
	}
	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	if _, err := t.Exec(ctx, r.ExecID, runtime.ExecOpts{
		Spec: r.Spec,
		IO: runtime.IO{
			Stdin:    r.Stdin,
			Stdout:   r.Stdout,
			Stderr:   r.Stderr,
			Terminal: r.Terminal,
		},
	}); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return empty, nil
}

func (l *local) ResizePty(ctx context.Context, r *api.ResizePtyRequest, _ ...grpc.CallOption) (*ptypes.Empty, error) {
	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	p := runtime.Process(t)
	if r.ExecID != "" {
		if p, err = t.Process(ctx, r.ExecID); err != nil {
			return nil, errdefs.ToGRPC(err)
		}
	}
	if err := p.ResizePty(ctx, runtime.ConsoleSize{
		Width:  r.Width,
		Height: r.Height,
	}); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return empty, nil
}

func (l *local) CloseIO(ctx context.Context, r *api.CloseIORequest, _ ...grpc.CallOption) (*ptypes.Empty, error) {
	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	p := runtime.Process(t)
	if r.ExecID != "" {
		if p, err = t.Process(ctx, r.ExecID); err != nil {
			return nil, errdefs.ToGRPC(err)
		}
	}
	if r.Stdin {
		if err := p.CloseIO(ctx); err != nil {
			return nil, errdefs.ToGRPC(err)
		}
	}
	return empty, nil
}

func (l *local) Checkpoint(ctx context.Context, r *api.CheckpointTaskRequest, _ ...grpc.CallOption) (*api.CheckpointTaskResponse, error) {
	container, err := l.getContainer(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	t, err := l.getTaskFromContainer(ctx, container)
	if err != nil {
		return nil, err
	}
	image, err := getCheckpointPath(container.Runtime.Name, r.Options)
	if err != nil {
		return nil, err
	}
	checkpointImageExists := false
	if image == "" {
		checkpointImageExists = true
		image, err = os.MkdirTemp(os.Getenv("XDG_RUNTIME_DIR"), "ctrd-checkpoint")
		if err != nil {
			return nil, errdefs.ToGRPC(err)
		}
		defer os.RemoveAll(image)
	}

	if r.ExportToArchive {
		// We do not want anyone accessing the checkpoint directory
		if err := os.MkdirAll(image, 0o700); err != nil {
			return nil, err
		}
		checkpointImageExists = true
		defer os.RemoveAll(image)
	}

	if err := t.Checkpoint(ctx, image, r.Options); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	// do not commit checkpoint image if checkpoint ImagePath is passed,
	// return if checkpointImageExists is false
	if !checkpointImageExists {
		return &api.CheckpointTaskResponse{}, nil
	}
	if r.ExportToArchive {
		// Remove '/checkpoint' so that the actual checkpoint is in the
		// checkpoint directory in the resulting archive.
		image = path.Dir(image)

		// Write spec to checkpoint archive
		if err := os.WriteFile(
			filepath.Join(image, crmetadata.SpecDumpFile),
			container.Spec.GetValue(),
			0600,
		); err != nil {
			return nil, err
		}
		// TODO: delete spec.dump, stats-dump dump.log
	}
	tar := archive.Diff(ctx, "", image)
	if r.ExportToArchive {
		// Write checkpoint to the external tar archive for Kubernetes support.
		// Checkpoint archive should also not be accessible by anyone else.
		outFile, err := os.OpenFile(r.Location, os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			return nil, err
		}
		defer outFile.Close()
		_, err = io.Copy(outFile, tar)
		if err != nil {
			return nil, err
		}
		if err := tar.Close(); err != nil {
			return nil, err
		}
		return &api.CheckpointTaskResponse{}, nil
	}
	// write checkpoint to the content store
	cp, err := l.writeContent(ctx, images.MediaTypeContainerd1Checkpoint, image, tar)
	// close tar first after write
	if err := tar.Close(); err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	// write the config to the content store
	pbany := protobuf.FromAny(container.Spec)
	data, err := proto.Marshal(pbany)
	if err != nil {
		return nil, err
	}
	spec := bytes.NewReader(data)
	specD, err := l.writeContent(ctx, images.MediaTypeContainerd1CheckpointConfig, filepath.Join(image, "spec"), spec)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return &api.CheckpointTaskResponse{
		Descriptors: []*types.Descriptor{
			cp,
			specD,
		},
	}, nil
}

func (l *local) Update(ctx context.Context, r *api.UpdateTaskRequest, _ ...grpc.CallOption) (*ptypes.Empty, error) {
	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	if err := t.Update(ctx, r.Resources, r.Annotations); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return empty, nil
}

func (l *local) Metrics(ctx context.Context, r *api.MetricsRequest, _ ...grpc.CallOption) (*api.MetricsResponse, error) {
	filter, err := filters.ParseAll(r.Filters...)
	if err != nil {
		return nil, err
	}
	var resp api.MetricsResponse
	for _, r := range l.allRuntimes() {
		tasks, err := r.Tasks(ctx, false)
		if err != nil {
			return nil, err
		}
		getTasksMetrics(ctx, filter, tasks, &resp)
	}
	return &resp, nil
}

func (l *local) Wait(ctx context.Context, r *api.WaitRequest, _ ...grpc.CallOption) (*api.WaitResponse, error) {
	t, err := l.getTask(ctx, r.ContainerID)
	if err != nil {
		return nil, err
	}
	p := runtime.Process(t)
	if r.ExecID != "" {
		if p, err = t.Process(ctx, r.ExecID); err != nil {
			return nil, errdefs.ToGRPC(err)
		}
	}
	exit, err := p.Wait(ctx)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return &api.WaitResponse{
		ExitStatus: exit.Status,
		ExitedAt:   protobuf.ToTimestamp(exit.Timestamp),
	}, nil
}

func getTasksMetrics(ctx context.Context, filter filters.Filter, tasks []runtime.Task, r *api.MetricsResponse) {
	for _, tk := range tasks {
		if !filter.Match(filters.AdapterFunc(func(fieldpath []string) (string, bool) {
			t := tk
			switch fieldpath[0] {
			case "id":
				return t.ID(), true
			case "namespace":
				return t.Namespace(), true
			case "runtime":
				// return t.Info().Runtime, true
			}
			return "", false
		})) {
			continue
		}
		collected := time.Now()
		stats, err := tk.Stats(ctx)
		if err != nil {
			if !errdefs.IsNotFound(err) {
				log.G(ctx).WithError(err).Errorf("collecting metrics for %s", tk.ID())
			}
			continue
		}
		r.Metrics = append(r.Metrics, &types.Metric{
			Timestamp: protobuf.ToTimestamp(collected),
			ID:        tk.ID(),
			Data:      stats,
		})
	}
}

func (l *local) writeContent(ctx context.Context, mediaType, ref string, r io.Reader) (*types.Descriptor, error) {
	writer, err := l.store.Writer(ctx, content.WithRef(ref), content.WithDescriptor(ocispec.Descriptor{MediaType: mediaType}))
	if err != nil {
		return nil, err
	}
	defer writer.Close()
	size, err := io.Copy(writer, r)
	if err != nil {
		return nil, err
	}
	if err := writer.Commit(ctx, 0, ""); err != nil {
		return nil, err
	}
	return &types.Descriptor{
		MediaType:   mediaType,
		Digest:      writer.Digest().String(),
		Size:        size,
		Annotations: make(map[string]string),
	}, nil
}

func (l *local) getContainer(ctx context.Context, id string) (*containers.Container, error) {
	var container containers.Container
	container, err := l.containers.Get(ctx, id)
	if err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	return &container, nil
}

func (l *local) getTask(ctx context.Context, id string) (runtime.Task, error) {
	container, err := l.getContainer(ctx, id)
	if err != nil {
		return nil, err
	}
	return l.getTaskFromContainer(ctx, container)
}

func (l *local) getTaskFromContainer(ctx context.Context, container *containers.Container) (runtime.Task, error) {
	runtime, err := l.getRuntime(container.Runtime.Name)
	if err != nil {
		return nil, errdefs.ToGRPCf(err, "runtime for task %s", container.Runtime.Name)
	}
	t, err := runtime.Get(ctx, container.ID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "task %v not found", container.ID)
	}
	return t, nil
}

func (l *local) getRuntime(name string) (runtime.PlatformRuntime, error) {
	runtime, ok := l.runtimes[name]
	if !ok {
		// one runtime to rule them all
		return l.v2Runtime, nil
	}
	return runtime, nil
}

func (l *local) allRuntimes() (o []runtime.PlatformRuntime) {
	for _, r := range l.runtimes {
		o = append(o, r)
	}
	o = append(o, l.v2Runtime)
	return o
}

// getCheckpointPath only suitable for runc runtime now
func getCheckpointPath(runtime string, option *ptypes.Any) (string, error) {
	if option == nil {
		return "", nil
	}

	var checkpointPath string
	switch {
	case checkRuntime(runtime, "io.containerd.runc"):
		v, err := typeurl.UnmarshalAny(option)
		if err != nil {
			return "", err
		}
		opts, ok := v.(*options.CheckpointOptions)
		if !ok {
			return "", fmt.Errorf("invalid task checkpoint option for %s", runtime)
		}
		checkpointPath = opts.ImagePath

	case runtime == plugin.RuntimeLinuxV1:
		v, err := typeurl.UnmarshalAny(option)
		if err != nil {
			return "", err
		}
		opts, ok := v.(*runctypes.CheckpointOptions)
		if !ok {
			return "", fmt.Errorf("invalid task checkpoint option for %s", runtime)
		}
		checkpointPath = opts.ImagePath
	}

	return checkpointPath, nil
}

// getRestorePath only suitable for runc runtime now
func getRestorePath(runtime string, option *ptypes.Any) (string, error) {
	if option == nil {
		return "", nil
	}

	var restorePath string
	switch {
	case checkRuntime(runtime, "io.containerd.runc"):
		v, err := typeurl.UnmarshalAny(option)
		if err != nil {
			return "", err
		}
		opts, ok := v.(*options.Options)
		if !ok {
			return "", fmt.Errorf("invalid task create option for %s", runtime)
		}
		restorePath = opts.CriuImagePath
	case runtime == plugin.RuntimeLinuxV1:
		v, err := typeurl.UnmarshalAny(option)
		if err != nil {
			return "", err
		}
		opts, ok := v.(*runctypes.CreateOptions)
		if !ok {
			return "", fmt.Errorf("invalid task create option for %s", runtime)
		}
		restorePath = opts.CriuImagePath
	}

	return restorePath, nil
}

// checkRuntime returns true if the current runtime matches the expected
// runtime. Providing various parts of the runtime schema will match those
// parts of the expected runtime
func checkRuntime(current, expected string) bool {
	cp := strings.Split(current, ".")
	l := len(cp)
	for i, p := range strings.Split(expected, ".") {
		if i > l {
			return false
		}
		if p != cp[i] {
			return false
		}
	}
	return true
}
