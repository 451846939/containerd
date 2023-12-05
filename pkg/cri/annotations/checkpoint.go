package annotations

const (
	// CheckpointAnnotationName is used by Container Checkpoint when creating a checkpoint image to specify the
	// original human-readable name for the container.
	CheckpointAnnotationName = "io.kubernetes.containerd.annotations.checkpoint.name"

	// CheckpointAnnotationRawImageName is used by Container Checkpoint when
	// creating a checkpoint image to specify the original unprocessed name of
	// the image used to create the container (as specified by the user).
	CheckpointAnnotationRawImageName = "io.kubernetes.containerd.annotations.checkpoint.rawImageName"

	// CheckpointAnnotationRootfsImageID is used by Container Checkpoint when
	// creating a checkpoint image to specify the original ID of the image used
	// to create the container.
	CheckpointAnnotationRootfsImageID = "io.kubernetes.containerd.annotations.checkpoint.rootfsImageID"

	// CheckpointAnnotationRootfsImageName is used by Container Checkpoint when
	// creating a checkpoint image to specify the original image name used to
	// create the container.
	CheckpointAnnotationRootfsImageName = "io.kubernetes.containerd.annotations.checkpoint.rootfsImageName"

	// CheckpointAnnotationCRIOVersion is used by Container Checkpoint when
	// creating a checkpoint image to specify the version of containerd used on the
	// host where the checkpoint was created.
	CheckpointAnnotationCRIOVersion = "io.kubernetes.containerd.annotations.checkpoint.containerd.version"

	// CheckpointAnnotationCriuVersion is used by Container Checkpoint when
	// creating a checkpoint image to specify the version of CRIU used on the
	// host where the checkpoint was created.
	CheckpointAnnotationCriuVersion = "io.kubernetes.containerd.annotations.checkpoint.criu.version"
)
