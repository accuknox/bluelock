package feeder

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	cfg "github.com/daemon1024/bluelock/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func getProtocolFromName(proto string) string {
	switch strings.ToLower(proto) {
	case "tcp":
		return "protocol=TCP,type=SOCK_STREAM"
	case "udp":
		return "protocol=UDP,type=SOCK_DGRAM"
	case "icmp":
		return "protocol=ICMP,type=SOCK_RAW"
	case "raw":
		return "type=SOCK_RAW"
	default:
		return "unknown"
	}
}

func getFileProcessUID(path string) string {
	info, err := os.Stat(path)
	if err == nil {
		stat := info.Sys().(*syscall.Stat_t)
		uid := stat.Uid

		return strconv.Itoa(int(uid))
	}

	return ""
}

func (fd *Feeder) newMatchPolicy(policyEnabled int, policyName, src string, mp interface{}) tp.MatchPolicy {
	match := tp.MatchPolicy{
		PolicyName: policyName,
		Source:     src,
	}

	if ppt, ok := mp.(tp.ProcessPathType); ok {
		match.Severity = strconv.Itoa(ppt.Severity)
		match.Tags = ppt.Tags
		match.Message = ppt.Message

		match.Operation = "Process"
		match.Resource = ppt.Path
		match.ResourceType = "Path"

		match.OwnerOnly = ppt.OwnerOnly

		if policyEnabled == tp.KubeArmorPolicyAudited && ppt.Action == "Allow" {
			match.Action = "Audit (" + ppt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && ppt.Action == "Block" {
			match.Action = "Audit (" + ppt.Action + ")"
		} else {
			match.Action = ppt.Action
		}
	} else if pdt, ok := mp.(tp.ProcessDirectoryType); ok {
		match.Severity = strconv.Itoa(pdt.Severity)
		match.Tags = pdt.Tags
		match.Message = pdt.Message

		match.Operation = "Process"
		match.Resource = pdt.Directory
		match.ResourceType = "Directory"

		match.OwnerOnly = pdt.OwnerOnly
		match.Recursive = pdt.Recursive

		if policyEnabled == tp.KubeArmorPolicyAudited && pdt.Action == "Allow" {
			match.Action = "Audit (" + pdt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && pdt.Action == "Block" {
			match.Action = "Audit (" + pdt.Action + ")"
		} else {
			match.Action = pdt.Action
		}
	} else if ppt, ok := mp.(tp.ProcessPatternType); ok {
		match.Severity = strconv.Itoa(ppt.Severity)
		match.Tags = ppt.Tags
		match.Message = ppt.Message

		match.Operation = "Process"
		match.Resource = ppt.Pattern
		match.ResourceType = "" // to be defined based on the pattern matching syntax

		match.OwnerOnly = ppt.OwnerOnly

		if policyEnabled == tp.KubeArmorPolicyAudited && ppt.Action == "Allow" {
			match.Action = "Audit (" + ppt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && ppt.Action == "Block" {
			match.Action = "Audit (" + ppt.Action + ")"
		} else {
			match.Action = ppt.Action
		}
	} else if fpt, ok := mp.(tp.FilePathType); ok {
		match.Severity = strconv.Itoa(fpt.Severity)
		match.Tags = fpt.Tags
		match.Message = fpt.Message

		match.Operation = "File"
		match.Resource = fpt.Path
		match.ResourceType = "Path"

		match.OwnerOnly = fpt.OwnerOnly
		match.ReadOnly = fpt.ReadOnly

		if policyEnabled == tp.KubeArmorPolicyAudited && fpt.Action == "Allow" {
			match.Action = "Audit (" + fpt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && fpt.Action == "Block" {
			match.Action = "Audit (" + fpt.Action + ")"
		} else {
			match.Action = fpt.Action
		}
	} else if fdt, ok := mp.(tp.FileDirectoryType); ok {
		match.Severity = strconv.Itoa(fdt.Severity)
		match.Tags = fdt.Tags
		match.Message = fdt.Message

		match.Operation = "File"
		match.Resource = fdt.Directory
		match.ResourceType = "Directory"

		match.OwnerOnly = fdt.OwnerOnly
		match.ReadOnly = fdt.ReadOnly
		match.Recursive = fdt.Recursive

		if policyEnabled == tp.KubeArmorPolicyAudited && fdt.Action == "Allow" {
			match.Action = "Audit (" + fdt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && fdt.Action == "Block" {
			match.Action = "Audit (" + fdt.Action + ")"
		} else {
			match.Action = fdt.Action
		}
	} else if fpt, ok := mp.(tp.FilePatternType); ok {
		match.Severity = strconv.Itoa(fpt.Severity)
		match.Tags = fpt.Tags
		match.Message = fpt.Message
		match.Operation = "File"
		match.Resource = fpt.Pattern
		match.ResourceType = "" // to be defined based on the pattern matching syntax

		match.OwnerOnly = fpt.OwnerOnly
		match.ReadOnly = fpt.ReadOnly

		if policyEnabled == tp.KubeArmorPolicyAudited && fpt.Action == "Allow" {
			match.Action = "Audit (" + fpt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && fpt.Action == "Block" {
			match.Action = "Audit (" + fpt.Action + ")"
		} else {
			match.Action = fpt.Action
		}
	} else if npt, ok := mp.(tp.NetworkProtocolType); ok {
		match.Severity = strconv.Itoa(npt.Severity)
		match.Tags = npt.Tags
		match.Message = npt.Message

		match.Operation = "Network"
		match.Resource = getProtocolFromName(npt.Protocol)
		match.ResourceType = "Protocol"

		if policyEnabled == tp.KubeArmorPolicyAudited && npt.Action == "Allow" {
			match.Action = "Audit (" + npt.Action + ")"
		} else if policyEnabled == tp.KubeArmorPolicyAudited && npt.Action == "Block" {
			match.Action = "Audit (" + npt.Action + ")"
		} else {
			match.Action = npt.Action
		}
	} else {
		return tp.MatchPolicy{}
	}

	return match
}

// UpdateSecurityPolicy Function
func (fd *Feeder) UpdateSecurityPolicy(action string, endPoint tp.EndPoint) {
	if action == "DELETED" {
		fd.SecurityPolicy = tp.MatchPolicies{}
		return
	}

	// ADDED | MODIFIED
	matches := tp.MatchPolicies{}

	for _, secPolicy := range endPoint.SecurityPolicies {
		policyName := secPolicy.Metadata["policyName"]

		for _, path := range secPolicy.Spec.Process.MatchPaths {
			fromSource := ""

			if len(path.FromSource) == 0 {
				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range path.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, path)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, dir := range secPolicy.Spec.Process.MatchDirectories {
			fromSource := ""

			if len(dir.FromSource) == 0 {
				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range dir.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, dir)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, patt := range secPolicy.Spec.Process.MatchPatterns {
			if len(patt.Pattern) == 0 {
				continue
			}

			fromSource := ""

			match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, patt)

			regexpComp, err := regexp.Compile(patt.Pattern)
			if err != nil {
				//fd.Debugf("MatchPolicy Regexp compilation error: %s\n", patt.Pattern)
				kg.Warnf("MatchPolicy Regexp compilation error: %s\n", patt.Pattern)
				continue
			}
			match.Regexp = regexpComp
			// Using 'Glob' despite compiling 'Regexp', since we don't have
			// a native pattern matching design yet and 'Glob' is more similar
			// to AppArmor's pattern matching syntax.
			match.ResourceType = "Glob"

			matches.Policies = append(matches.Policies, match)
		}

		for _, path := range secPolicy.Spec.File.MatchPaths {
			fromSource := ""

			if len(path.FromSource) == 0 {
				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, path)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range path.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, path)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, dir := range secPolicy.Spec.File.MatchDirectories {
			fromSource := ""

			if len(dir.FromSource) == 0 {
				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, dir)
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range dir.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, dir)
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}

		for _, patt := range secPolicy.Spec.File.MatchPatterns {
			if len(patt.Pattern) == 0 {
				continue
			}

			fromSource := ""

			match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, patt)

			regexpComp, err := regexp.Compile(patt.Pattern)
			if err != nil {
				kg.Warnf("MatchPolicy Regexp compilation error: %s\n", patt.Pattern)
				continue
			}
			match.Regexp = regexpComp
			// Using 'Glob' despite compiling 'Regexp', since we don't have
			// a native pattern matching design yet and 'Glob' is more similar
			// to AppArmor's pattern matching syntax.
			match.ResourceType = "Glob"

			matches.Policies = append(matches.Policies, match)
		}

		for _, proto := range secPolicy.Spec.Network.MatchProtocols {
			if len(proto.Protocol) == 0 {
				continue
			}

			fromSource := ""

			if len(proto.FromSource) == 0 {
				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, proto)
				if len(match.Resource) == 0 {
					continue
				}
				matches.Policies = append(matches.Policies, match)
				continue
			}

			for _, src := range proto.FromSource {
				if len(src.Path) > 0 {
					fromSource = src.Path
				} else {
					continue
				}

				match := fd.newMatchPolicy(endPoint.PolicyEnabled, policyName, fromSource, proto)
				if len(match.Resource) == 0 {
					continue
				}
				match.IsFromSource = len(fromSource) > 0
				matches.Policies = append(matches.Policies, match)
			}
		}
	}

	fd.SecurityPolicy = matches
}

func getDirectoryPart(path string) string {
	dir := filepath.Dir(path)
	if strings.HasPrefix(dir, "/") {
		return dir + "/"
	}
	return "__not_absolute_path__"
}

// Update Log Fields based on default posture and visibility configuration and return false if no updates
func setLogFields(log *tp.Log, existAllowPolicy bool, defaultPosture string, visibility bool) {
	if existAllowPolicy && defaultPosture == "audit" && (*log).Result == "Passed" {
		(*log).Type = "MatchedPolicy"

		(*log).PolicyName = "DefaultPosture"
		(*log).Enforcer = PtraceTracer
		(*log).Action = "Audit"
	} else {
		(*log).Type = "ContainerLog"
	}
}

func (fd *Feeder) UpdateMatchedPolicy(log tp.Log) tp.Log {
	existFileAllowPolicy := false
	existNetworkAllowPolicy := false

	if log.Result == "Passed" || log.Result == "Operation not permitted" || log.Result == "Permission denied" {

		// host mode/ECS
		//key := cfg.GlobalCfg.Host
		//if log.NamespaceName != "" && log.PodName != "" {
		//	key = log.NamespaceName + "_" + log.PodName
		//}

		secPolicies := fd.SecurityPolicy.Policies
		for _, secPolicy := range secPolicies {
			if secPolicy.Action == "Allow" || secPolicy.Action == "Audit (Allow)" {
				if secPolicy.Operation == "Process" || secPolicy.Operation == "File" {
					existFileAllowPolicy = true
				} else if secPolicy.Operation == "Network" {
					existNetworkAllowPolicy = true
				}

				if fd.DefaultPosture.FileAction == "allow" {
					continue
				}
			}

			firstLogResource := strings.Split(log.Resource, " ")[0]
			firstLogResourceDir := getDirectoryPart(firstLogResource)
			firstLogResourceDirCount := strings.Count(firstLogResourceDir, "/")

			switch log.Operation {
			case "Process", "File":
				if secPolicy.Operation != log.Operation {
					continue
				}

				// match sources
				if (!secPolicy.IsFromSource) || (secPolicy.IsFromSource && (secPolicy.Source == log.ParentProcessName || secPolicy.Source == log.ProcessName)) {
					matchedRegex := false

					switch secPolicy.ResourceType {
					case "Glob":
						// Match using a globbing syntax very similar to the AppArmor's
						matchedRegex, _ = filepath.Match(secPolicy.Resource, log.Resource) // pattern (secPolicy.Resource) -> string (log.Resource)
					case "Regexp":
						if secPolicy.Regexp != nil {
							// Match using compiled regular expression
							matchedRegex = secPolicy.Regexp.MatchString(log.Resource) // regexp (secPolicy.Regexp) -> string (log.Resource)
						}
					}

					// match resources
					if matchedRegex || (secPolicy.ResourceType == "Path" && secPolicy.Resource == firstLogResource) ||
						(secPolicy.ResourceType == "Directory" && strings.HasPrefix(firstLogResourceDir, secPolicy.Resource) &&
							((!secPolicy.Recursive && firstLogResourceDirCount == strings.Count(secPolicy.Resource, "/")) ||
								(secPolicy.Recursive && firstLogResourceDirCount >= strings.Count(secPolicy.Resource, "/")))) {

						matchedFlags := false

						if secPolicy.ReadOnly && log.Resource != "" && secPolicy.OwnerOnly && log.MergedDir != "" {
							// read only && owner only
							if strings.Contains(log.Data, "O_RDONLY") && strconv.Itoa(int(log.UID)) == getFileProcessUID(log.MergedDir+log.Resource) {
								matchedFlags = true
							}
						} else if secPolicy.ReadOnly && log.Resource != "" {
							// read only
							if strings.Contains(log.Data, "O_RDONLY") {
								matchedFlags = true
							}
						} else if secPolicy.OwnerOnly && log.MergedDir != "" {
							// owner only
							if strconv.Itoa(int(log.UID)) == getFileProcessUID(log.MergedDir+log.Resource) {
								matchedFlags = true
							}
						} else {
							// ! read only && ! owner only
							matchedFlags = true
						}

						if matchedFlags && (secPolicy.Action == "Allow" || secPolicy.Action == "Audit (Allow)") && log.Result == "Passed" {
							// allow policy or allow policy with audit mode
							// matched source + matched resource + matched flags + matched action + expected result -> going to be skipped

							log.Type = "MatchedPolicy"

							log.PolicyName = secPolicy.PolicyName
							log.Severity = secPolicy.Severity

							if len(secPolicy.Tags) > 0 {
								log.Tags = strings.Join(secPolicy.Tags[:], ",")
								log.ATags = secPolicy.Tags
							}

							if len(secPolicy.Message) > 0 {
								log.Message = secPolicy.Message
							}

							if log.PolicyEnabled == tp.KubeArmorPolicyAudited {
								log.Enforcer = PtraceTracer
							} else {
								log.Enforcer = PtraceEnforcer
							}

							log.Action = "Allow"

							continue
						}

						if matchedFlags && secPolicy.Action == "Audit" && log.Result == "Passed" {
							// audit policy
							// matched source + matched resource + matched flags + matched action + expected result -> alert (audit log)

							log.Type = "MatchedPolicy"

							log.PolicyName = secPolicy.PolicyName
							log.Severity = secPolicy.Severity

							if len(secPolicy.Tags) > 0 {
								log.Tags = strings.Join(secPolicy.Tags[:], ",")
								log.ATags = secPolicy.Tags
							}

							if len(secPolicy.Message) > 0 {
								log.Message = secPolicy.Message
							}

							log.Enforcer = PtraceTracer
							log.Action = secPolicy.Action

							continue
						}

						if (secPolicy.Action == "Block" && log.Result != "Passed") ||
							(matchedFlags && (!secPolicy.OwnerOnly && !secPolicy.ReadOnly) && secPolicy.Action == "Audit (Block)" && log.Result == "Passed") ||
							(!matchedFlags && (secPolicy.OwnerOnly || secPolicy.ReadOnly) && secPolicy.Action == "Audit (Block)" && log.Result == "Passed") {
							// block policy or block policy with audit mode
							// matched source + matched resource + matched action + expected result -> alert

							log.Type = "MatchedPolicy"

							log.PolicyName = secPolicy.PolicyName
							log.Severity = secPolicy.Severity

							if len(secPolicy.Tags) > 0 {
								log.Tags = strings.Join(secPolicy.Tags[:], ",")
								log.ATags = secPolicy.Tags
							}

							if len(secPolicy.Message) > 0 {
								log.Message = secPolicy.Message
							}

							if log.PolicyEnabled == tp.KubeArmorPolicyAudited {
								log.Enforcer = PtraceTracer
							} else {
								log.Enforcer = PtraceEnforcer
							}

							log.Action = secPolicy.Action

							continue
						}

						if matchedFlags && secPolicy.Action == "Allow" && log.Result != "Passed" {
							// It's possible there are additional rules in the Security Policy resulting in the block else we deem it as default posture anyway
							continue
						}
					}

					if secPolicy.Action == "Allow" && log.Result != "Passed" {
						// matched source + !(matched resource) + action = allow + result = blocked -> default posture / allow policy violation

						log.Type = "MatchedPolicy"

						log.PolicyName = "DefaultPosture"

						log.Severity = ""
						log.Tags = ""
						log.ATags = []string{}
						log.Message = ""

						log.Enforcer = PtraceTracer
						log.Action = "Block"

						continue
					}

					if secPolicy.Action == "Audit (Allow)" && log.Result == "Passed" {
						// matched source + !(matched resource) + action = audit (allow) + result = passed -> default posture / allow policy violation (audit mode)

						log.Type = "MatchedPolicy"

						log.PolicyName = "DefaultPosture"

						log.Severity = ""
						log.Tags = ""
						log.ATags = []string{}
						log.Message = ""

						log.Enforcer = PtraceTracer

						if fd.DefaultPosture.FileAction == "block" {
							log.Action = "Audit (Block)"
						} else { // fd.DefaultPosture[log.NamespaceName].FileAction == "audit"
							log.Action = "Audit"
						}

						continue
					}
				}

				if fd.DefaultPosture.FileAction == "block" && secPolicy.Action == "Audit (Allow)" && log.Result == "Passed" {
					// defaultPosture = block + audit mode

					log.Type = "MatchedPolicy"

					log.PolicyName = "DefaultPosture"

					log.Severity = ""
					log.Tags = ""
					log.ATags = []string{}
					log.Message = ""

					log.Enforcer = PtraceTracer
					log.Action = "Audit (Block)"
				}

				if fd.DefaultPosture.FileAction == "audit" && (secPolicy.Action == "Allow" || secPolicy.Action == "Audit (Allow)") && log.Result == "Passed" {
					// defaultPosture = audit

					log.Type = "MatchedPolicy"

					log.PolicyName = "DefaultPosture"

					log.Severity = ""
					log.Tags = ""
					log.ATags = []string{}
					log.Message = ""

					log.Enforcer = PtraceTracer
					log.Action = "Audit"
				}

			case "Network":
				if secPolicy.Operation != log.Operation {
					continue
				}

				// match sources
				if (!secPolicy.IsFromSource) || (secPolicy.IsFromSource && (secPolicy.Source == log.ParentProcessName || secPolicy.Source == log.ProcessName)) {
					skip := false

					for _, matchProtocol := range strings.Split(secPolicy.Resource, ",") {
						if skip {
							break
						}

						// match resources
						if strings.Contains(log.Resource, matchProtocol) {
							if (secPolicy.Action == "Allow" || secPolicy.Action == "Audit (Allow)") && log.Result == "Passed" {
								// allow policy or allow policy with audit mode
								// matched source + matched resource + matched action + expected result -> going to be skipped

								log.Type = "MatchedPolicy"

								log.PolicyName = secPolicy.PolicyName
								log.Severity = secPolicy.Severity

								if len(secPolicy.Tags) > 0 {
									log.Tags = strings.Join(secPolicy.Tags[:], ",")
									log.ATags = secPolicy.Tags
								}

								if len(secPolicy.Message) > 0 {
									log.Message = secPolicy.Message
								}

								if log.PolicyEnabled == tp.KubeArmorPolicyAudited {
									log.Enforcer = PtraceTracer
								} else {
									log.Enforcer = PtraceEnforcer
								}

								log.Action = "Allow"

								skip = true
								continue
							}

							if secPolicy.Action == "Audit" && log.Result == "Passed" {
								// audit policy
								// matched source + matched resource + matched action + expected result -> alert (audit log)

								log.Type = "MatchedPolicy"

								log.PolicyName = secPolicy.PolicyName
								log.Severity = secPolicy.Severity

								if len(secPolicy.Tags) > 0 {
									log.Tags = strings.Join(secPolicy.Tags[:], ",")
									log.ATags = secPolicy.Tags
								}

								if len(secPolicy.Message) > 0 {
									log.Message = secPolicy.Message
								}

								log.Enforcer = PtraceTracer
								log.Action = secPolicy.Action

								skip = true
								continue
							}

							if (secPolicy.Action == "Block" && log.Result != "Passed") ||
								(secPolicy.Action == "Audit (Block)" && log.Result == "Passed") {
								// block policy or block policy with audit mode
								// matched source + matched resource + matched action + expected result -> alert

								log.Type = "MatchedPolicy"

								log.PolicyName = secPolicy.PolicyName
								log.Severity = secPolicy.Severity

								if len(secPolicy.Tags) > 0 {
									log.Tags = strings.Join(secPolicy.Tags[:], ",")
								}

								if len(secPolicy.Message) > 0 {
									log.Message = secPolicy.Message
								}

								if log.PolicyEnabled == tp.KubeArmorPolicyAudited {
									log.Enforcer = PtraceTracer
								} else {
									log.Enforcer = PtraceEnforcer
								}

								log.Action = secPolicy.Action

								skip = true
								continue
							}
						}
					}

					if skip {
						continue
					}

					if secPolicy.Action == "Allow" && log.Result != "Passed" {
						// matched source + !(matched resource) + action = allow + result = blocked -> allow policy violation

						log.Type = "MatchedPolicy"

						log.PolicyName = "DefaultPosture"

						log.Severity = ""
						log.Tags = ""
						log.Message = ""

						log.Enforcer = PtraceTracer
						log.Action = "Block"

						continue
					}

					if secPolicy.Action == "Audit (Allow)" && log.Result == "Passed" {
						// matched source + !(matched resource) + action = audit (allow) + result = passed -> allow policy violation (audit mode)

						log.Type = "MatchedPolicy"

						log.PolicyName = "DefaultPosture"

						log.Severity = ""
						log.Tags = ""
						log.Message = ""

						log.Enforcer = PtraceTracer

						if fd.DefaultPosture.NetworkAction == "block" {
							log.Action = "Audit (Block)"
						} else { // fd.DefaultPosture[log.NamespaceName].NetworkAction == "audit"
							log.Action = "Audit"
						}

						continue
					}
				}

				if fd.DefaultPosture.NetworkAction == "block" && secPolicy.Action == "Audit (Allow)" && log.Result == "Passed" {
					// defaultPosture = block + audit mode

					log.Type = "MatchedPolicy"

					log.PolicyName = "DefaultPosture"

					log.Severity = ""
					log.Tags = ""
					log.Message = ""

					log.Enforcer = PtraceTracer
					log.Action = "Audit (Block)"
				}

				if fd.DefaultPosture.NetworkAction == "audit" && (secPolicy.Action == "Allow" || secPolicy.Action == "Audit (Allow)") && log.Result == "Passed" {
					// defaultPosture = audit

					log.Type = "MatchedPolicy"

					log.PolicyName = "DefaultPosture"

					log.Severity = ""
					log.Tags = ""
					log.Message = ""

					log.Enforcer = PtraceEnforcer
					log.Action = "Audit"
				}
			}
		}

		if log.PolicyName == "" && log.Result != "Passed" {
			// default posture (block) or native policy
			// no matched policy, but result = blocked -> default posture

			log.Type = "MatchedPolicy"

			log.PolicyName = "DefaultPosture"

			log.Severity = ""
			log.Tags = ""
			log.ATags = []string{}
			log.Message = ""

			log.Enforcer = PtraceEnforcer
			log.Action = "Block"
		}
	}

	if log.ContainerID != "" { // container
		if log.Type == "" {
			// defaultPosture (audit) or container log

			if fd.DefaultPosture != (tp.DefaultPosture{}) {
				globalDefaultPosture := tp.DefaultPosture{
					FileAction:         cfg.GlobalCfg.DefaultFilePosture,
					NetworkAction:      cfg.GlobalCfg.DefaultNetworkPosture,
				}
				fd.DefaultPosture = globalDefaultPosture
			}

			if log.Operation == "Process" {
				setLogFields(&log, existFileAllowPolicy, fd.DefaultPosture.FileAction, true)
				return log
			} else if log.Operation == "File" {
				setLogFields(&log, existFileAllowPolicy, fd.DefaultPosture.FileAction, true)
				return log
			} else if log.Operation == "Network" {
				setLogFields(&log, existNetworkAllowPolicy, fd.DefaultPosture.NetworkAction, true)
				return log
			}

		} else if log.Type == "MatchedPolicy" {
			if log.Action == "Allow" && log.Result == "Passed" {
				return tp.Log{}
			}
			fmt.Println("MatchedPolicy")

			return log
		}
	}

	return tp.Log{}
}
