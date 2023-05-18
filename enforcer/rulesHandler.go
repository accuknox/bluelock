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
	Dir, Hint, Recursive, ReadOnly, OwnerOnly, Deny, Allow bool
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

		// parse durectory rules
		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			var rc RuleConfig

			rc.OwnerOnly = dir.OwnerOnly
			rc.ReadOnly = dir.ReadOnly
			rc.Recursive = dir.Recursive

			if len(dir.FromSource) == 0 {
				if dir.Action == "Allow" {
					if defaultPosture.FileAction == "block" {
						newRules.FileWhiteListPosture = true
					}
					rc.Allow = true
					rc.Deny = false
				} else if dir.Action == "Block" {
					rc.Allow = false
					rc.Deny = true
				}
				dirtoMap(InnerKey{Path: dir.Directory}, newRules.FileRules, rc)
			} else {
				for _, src := range dir.FromSource {
					if dir.Action == "Allow" {
						if defaultPosture.FileAction == "block" {
							newRules.FileWhiteListPosture = true
						}
						rc.Allow = true
						rc.Deny = false
					} else if dir.Action == "Block" {
						rc.Allow = false
						rc.Deny = true
					}
					dirtoMap(InnerKey{Path: dir.Directory, Source: src.Path}, newRules.FileRules, rc)
				}
			}
		}
	}

	pe.Rules = newRules
}

// dirtoMap extracts parent directories from the Path Key and adds it as hints in the Container Rule Map
func dirtoMap(dirKey InnerKey, m map[InnerKey]RuleConfig, val RuleConfig) {
	key := dirKey
	paths := strings.Split(dirKey.Path, "/")

	// Add the directory itself but kernel space would refer it as a file so...
	key.Path = strings.Join(paths[0:len(paths)-1], "/")
	m[key] = val

	key.Path = dirKey.Path
	val.Dir = true
	if oldval, ok := m[key]; ok {
		if oldval.Hint {
			val.Hint = true
		}
	}
	m[key] = val

	for i := 1; i < len(paths)-1; i++ {
		var key InnerKey
		val.Dir = false
		val.Hint = true
		key.Path = strings.Join(paths[0:i], "/") + "/"
		if oldval, ok := m[key]; ok {
			val.Dir = oldval.Dir
		}
		m[key] = val
	}
}
