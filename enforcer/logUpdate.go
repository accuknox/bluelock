package enforcer

import (
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func (t *Tracer) NewBaseLog() tp.Log {
	log := tp.Log{}

	timestamp, updatedTime := kl.GetDateTimeNow()

	log.Timestamp = timestamp
	log.UpdatedTime = updatedTime

	container := t.Container
	log.NamespaceName = container.NamespaceName
	log.PodName = container.EndPointName
	log.Labels = container.Labels

	log.ContainerName = container.ContainerName
	log.ContainerImage = container.ContainerImage
	log.ContainerID = container.ContainerID

	log.PolicyEnabled = container.PolicyEnabled

	log.ProcessVisibilityEnabled = container.ProcessVisibilityEnabled
	log.FileVisibilityEnabled = container.FileVisibilityEnabled
	log.NetworkVisibilityEnabled = container.NetworkVisibilityEnabled
	log.CapabilitiesVisibilityEnabled = container.CapabilitiesVisibilityEnabled

	log.Result = "Passed"

	return log
}
