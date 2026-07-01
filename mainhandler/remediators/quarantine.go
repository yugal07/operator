package remediators

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/armosec/armoapi-go/apis"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// LabelQuarantine marks the deny-all NetworkPolicy created by the quarantine
	// action, so it can be found and removed on revert.
	LabelQuarantine = "kubescape.io/quarantine"
	// AnnotationQuarantineTarget records, on the NetworkPolicy, the workload it
	// isolates — part of the audit trail.
	AnnotationQuarantineTarget = "kubescape.io/quarantine-target"

	// quarantineNPPrefix is the deterministic name prefix of the deny-all
	// NetworkPolicy, so revert can locate it from the target name alone.
	quarantineNPPrefix = "kubescape-quarantine-"
	// maxNameLen is the Kubernetes object-name length limit.
	maxNameLen = 253
)

// QuarantineRemediator isolates a workload by creating a deny-all NetworkPolicy
// that selects the workload's pods (both ingress and egress denied). It does
// not mutate or recreate the pods, so container state is preserved for forensic
// investigation (the design's resolved default; scale-to-zero is a future,
// explicit opt-in). Revert deletes the NetworkPolicy.
type QuarantineRemediator struct {
	client kubernetes.Interface
}

// NewQuarantineRemediator returns a quarantine remediator backed by client.
func NewQuarantineRemediator(client kubernetes.Interface) *QuarantineRemediator {
	return &QuarantineRemediator{client: client}
}

// Plan reads the target workload's pod selector from the live object and
// computes the deny-all NetworkPolicy without creating it.
func (r *QuarantineRemediator) Plan(ctx context.Context, req Request) (Plan, error) {
	if err := validateTarget(req.Target); err != nil {
		return Plan{}, err
	}
	selector, err := r.resolvePodSelector(ctx, req.Target)
	if err != nil {
		return Plan{}, err
	}
	np := r.buildNetworkPolicy(req, selector)
	body, err := json.Marshal(np)
	if err != nil {
		return Plan{}, err
	}
	return Plan{
		Action:      string(apis.OperatorActionQuarantine),
		Target:      req.Target,
		Description: fmt.Sprintf("deny-all NetworkPolicy %q isolating %s (podSelector %s)", np.Name, req.Target, metav1.FormatLabelSelector(selector)),
		Patch:       string(body),
	}, nil
}

// Apply creates the planned deny-all NetworkPolicy. With dryRun=true it is sent
// as a server-side dry-run (validated against admission, never persisted); only
// dryRun=false performs a real write. An existing policy is treated as success
// (the workload is already isolated by a prior quarantine).
func (r *QuarantineRemediator) Apply(ctx context.Context, p Plan, dryRun bool) (Result, error) {
	var np networkingv1.NetworkPolicy
	if err := json.Unmarshal([]byte(p.Patch), &np); err != nil {
		return Result{}, fmt.Errorf("quarantine: failed to decode planned NetworkPolicy: %w", err)
	}
	opts := metav1.CreateOptions{}
	if dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}
	_, err := r.client.NetworkingV1().NetworkPolicies(np.Namespace).Create(ctx, &np, opts)
	switch {
	case err == nil, apierrors.IsAlreadyExists(err):
		// created, or already isolated by a prior quarantine — both are success.
	default:
		return Result{}, fmt.Errorf("quarantine: failed to create NetworkPolicy %q: %w", np.Name, err)
	}
	return Result{
		Action:      p.Action,
		Target:      p.Target,
		DryRun:      dryRun,
		Applied:     !dryRun,
		Description: p.Description,
	}, nil
}

// Revert deletes the deny-all NetworkPolicy that quarantined the target. A
// missing policy is treated as success (nothing to undo). Like Apply, dryRun=true
// issues a server-side dry-run delete, so the safe-by-default contract holds for
// revert too.
func (r *QuarantineRemediator) Revert(ctx context.Context, t Target, dryRun bool) (Result, error) {
	if err := validateTarget(t); err != nil {
		return Result{}, err
	}
	name := quarantineNPName(t)
	opts := metav1.DeleteOptions{}
	if dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}
	err := r.client.NetworkingV1().NetworkPolicies(t.Namespace).Delete(ctx, name, opts)
	applied := !dryRun
	desc := fmt.Sprintf("deleted quarantine NetworkPolicy %q in namespace %q", name, t.Namespace)
	switch {
	case apierrors.IsNotFound(err):
		applied = false
		desc = fmt.Sprintf("no quarantine NetworkPolicy %q in namespace %q; nothing to revert", name, t.Namespace)
	case err != nil:
		return Result{}, fmt.Errorf("quarantine: failed to delete NetworkPolicy %q: %w", name, err)
	}
	return Result{
		Action:      string(apis.OperatorActionRevert),
		Target:      t,
		DryRun:      dryRun,
		Applied:     applied,
		Description: desc,
	}, nil
}

// resolvePodSelector returns the label selector that selects the target's
// running pods, read from the live object so quarantine isolates the existing
// pods without recreating them. The full selector (both matchLabels and
// matchExpressions) is preserved so workloads using set-based selectors are
// isolated correctly.
func (r *QuarantineRemediator) resolvePodSelector(ctx context.Context, t Target) (*metav1.LabelSelector, error) {
	var selector *metav1.LabelSelector
	switch strings.ToLower(t.Kind) {
	case "deployment":
		o, err := r.client.AppsV1().Deployments(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		selector = o.Spec.Selector
	case "statefulset":
		o, err := r.client.AppsV1().StatefulSets(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		selector = o.Spec.Selector
	case "daemonset":
		o, err := r.client.AppsV1().DaemonSets(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		selector = o.Spec.Selector
	case "pod":
		o, err := r.client.CoreV1().Pods(t.Namespace).Get(ctx, t.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		selector = &metav1.LabelSelector{MatchLabels: o.Labels}
	default:
		return nil, fmt.Errorf("quarantine: unsupported target kind %q (supported: Deployment, StatefulSet, DaemonSet, Pod)", t.Kind)
	}
	if selector == nil || (len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0) {
		return nil, fmt.Errorf("quarantine: %s has no pod selector labels to isolate; cannot build a NetworkPolicy", t)
	}
	return selector, nil
}

// buildNetworkPolicy assembles the deny-all NetworkPolicy: it selects the
// target's pods and declares both policy types with no allow rules, which denies
// all ingress and egress. Audit context is recorded in its labels/annotations.
func (r *QuarantineRemediator) buildNetworkPolicy(req Request, selector *metav1.LabelSelector) *networkingv1.NetworkPolicy {
	annotations := map[string]string{AnnotationQuarantineTarget: req.Target.String()}
	if req.Reason != "" {
		annotations[AnnotationReason] = req.Reason
	}
	if req.FindingRef != "" {
		annotations[AnnotationFindingRef] = req.FindingRef
	}
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        quarantineNPName(req.Target),
			Namespace:   req.Target.Namespace,
			Labels:      map[string]string{LabelQuarantine: "true"},
			Annotations: annotations,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: *selector,
			// Both policy types selected with no ingress/egress rules => deny all.
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
		},
	}
}

// quarantineNPName derives the deterministic deny-all NetworkPolicy name for a
// target so revert can find it from the target identity alone. The name is keyed
// on both kind and name so different kinds sharing a name (e.g. Deployment/api
// and StatefulSet/api) do not collide on — or delete — each other's policy. It
// is kept within the object-name length limit; when truncation is needed a short
// hash of the full identity is appended to keep distinct targets distinct.
func quarantineNPName(t Target) string {
	base := quarantineNPPrefix + strings.ToLower(t.Kind) + "-" + t.Name
	if len(base) <= maxNameLen {
		return base
	}
	sum := sha256.Sum256([]byte(t.String()))
	suffix := "-" + hex.EncodeToString(sum[:])[:10]
	return strings.TrimRight(base[:maxNameLen-len(suffix)], "-.") + suffix
}
