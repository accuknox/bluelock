package enforcer

import (
	"strings"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

type RuleSet struct {
	ProcessRules         map[InnerKey]RuleConfig
	FileRules            map[InnerKey]RuleConfig
	NetworkRules         map[InnerKey]RuleConfig
	ProcWhiteListPosture bool
	FileWhiteListPosture bool
	NetWhiteListPosture  bool
}

type InnerKey struct {
	Path   string
	Source string
}

type RuleConfig struct {
	Dir, Recursive, ReadOnly, OwnerOnly, Deny, Allow bool
}

func CreateNewRuleSet() (r *RuleSet) {
	r = new(RuleSet)
	r.ProcessRules = make(map[InnerKey]RuleConfig)
	r.FileRules = make(map[InnerKey]RuleConfig)
	r.NetworkRules = make(map[InnerKey]RuleConfig)
	return r
}

func (pe *PtraceEnforcer) UpdateRules(securityPolicies []tp.SecurityPolicy, defaultPosture tp.DefaultPosture) {
	newRules := CreateNewRuleSet()

	for _, secPolicy := range securityPolicies {

		// parse file rules
		for _, path := range secPolicy.Spec.File.MatchPaths {
			var rc RuleConfig

			rc.OwnerOnly = path.OwnerOnly
			rc.ReadOnly = path.ReadOnly

			if len(path.FromSource) == 0 {
				if path.Action == "Allow" {
					if defaultPosture.FileAction == "block" {
						newRules.FileWhiteListPosture = true
					}
					rc.Allow = true
					rc.Deny = false
				} else if path.Action == "Block" {
					rc.Allow = false
					rc.Deny = true
				}
				key := InnerKey{
					Path:   path.Path,
					Source: "",
				}
				newRules.FileRules[key] = rc
			} else {
				for _, src := range path.FromSource {
					if path.Action == "Allow" {
						if defaultPosture.FileAction == "block" {
							newRules.FileWhiteListPosture = true
						}
						rc.Allow = true
						rc.Deny = false
					} else if path.Action == "Block" {
						rc.Allow = false
						rc.Deny = true
					}
					key := InnerKey{
						Path:   path.Path,
						Source: src.Path,
					}
					newRules.FileRules[key] = rc
				}
			}
		}

		for _, path := range secPolicy.Spec.Process.MatchPaths {
			var rc RuleConfig

			rc.OwnerOnly = path.OwnerOnly

			if len(path.FromSource) == 0 {
				if path.Action == "Allow" {
					if defaultPosture.FileAction == "block" {
						newRules.ProcWhiteListPosture = true
					}
					rc.Allow = true
					rc.Deny = false
				} else if path.Action == "Block" {
					rc.Allow = false
					rc.Deny = true
				}
				key := InnerKey{
					Path:   path.Path,
					Source: "",
				}
				newRules.ProcessRules[key] = rc
			} else {
				for _, src := range path.FromSource {
					if path.Action == "Allow" {
						if defaultPosture.FileAction == "block" {
							newRules.ProcWhiteListPosture = true
						}
						rc.Allow = true
						rc.Deny = false
					} else if path.Action == "Block" {
						rc.Allow = false
						rc.Deny = true
					}
					key := InnerKey{
						Path:   path.Path,
						Source: src.Path,
					}
					newRules.ProcessRules[key] = rc
				}
			}
		}

		for _, net := range secPolicy.Spec.Network.MatchProtocols {
			var rc RuleConfig

			if len(net.FromSource) == 0 {
				if net.Action == "Allow" {
					if defaultPosture.NetworkAction == "block" {
						newRules.NetWhiteListPosture = true
					}
					rc.Allow = true
					rc.Deny = false
				} else if net.Action == "Block" {
					rc.Allow = false
					rc.Deny = true
				}
				key := InnerKey{
					Path:   strings.ToLower(net.Protocol),
					Source: "",
				}
				newRules.NetworkRules[key] = rc
			} else {
				for _, src := range net.FromSource {
					if net.Action == "Allow" {
						if defaultPosture.NetworkAction == "block" {
							newRules.NetWhiteListPosture = true
						}
						rc.Allow = true
						rc.Deny = false
					} else if net.Action == "Block" {
						rc.Allow = false
						rc.Deny = true
					}
					key := InnerKey{
						Path:   strings.ToLower(net.Protocol),
						Source: src.Path,
					}
					newRules.NetworkRules[key] = rc
				}
			}
		}
	}

	fuseProcAndFileRules(newRules.FileRules, newRules.ProcessRules)

	resolveConflicts(pe.Rules.FileRules, newRules.FileRules)
	resolveConflicts(pe.Rules.ProcessRules, newRules.ProcessRules)
	resolveConflicts(pe.Rules.NetworkRules, newRules.NetworkRules)

	pe.Rules = newRules
}

func fuseProcAndFileRules(procList, fileList map[InnerKey]RuleConfig) {
	for k := range fileList {
		if val, ok := procList[k]; ok {
			fileList[k] = val
		}
	}
}

func resolveConflicts(oldRules, newRules map[InnerKey]RuleConfig) {
	for key := range oldRules {
		if _, ok := newRules[key]; !ok {
			delete(oldRules, key)
		}
	}
}
