package cel_test

import (
	"testing"

	armotypes "github.com/armosec/armoapi-go/armotypes"
	admissioncel "github.com/kubescape/operator/admission/cel"
	celrules "github.com/kubescape/operator/admission/rules/cel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
)

// newIntegrationEngine creates a real AdmissionCEL engine, failing the test on error.
func newIntegrationEngine(t *testing.T) *admissioncel.AdmissionCEL {
	t.Helper()
	engine, err := admissioncel.NewAdmissionCEL()
	require.NoError(t, err, "NewAdmissionCEL")
	return engine
}

// newIntegrationCreator returns a CelRuleCreator backed by the provided engine.
func newIntegrationCreator(t *testing.T, engine *admissioncel.AdmissionCEL) *celrules.CelRuleCreator {
	t.Helper()
	return celrules.NewCelRuleCreator(engine)
}

// buildAttrs constructs an admission.Attributes record suitable for integration tests.
func buildAttrs(
	kind, name, namespace, subresource string,
	op admission.Operation,
	obj map[string]interface{},
	username string,
) admission.Attributes {
	gvk := schema.GroupVersionKind{Group: "", Version: "v1", Kind: kind}
	gvr := schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	var u *unstructured.Unstructured
	if obj != nil {
		u = &unstructured.Unstructured{Object: obj}
	}
	userInfo := &user.DefaultInfo{
		Name:   username,
		Groups: []string{"system:authenticated"},
		UID:    "uid-integration",
	}
	return admission.NewAttributesRecord(u, nil, gvk, namespace, name, gvr, subresource,
		op, nil, false, userInfo)
}

// TestIntegration_ExecToPod_CELRule validates the full pipeline for a PodExecOptions event.
func TestIntegration_ExecToPod_CELRule(t *testing.T) {
	engine := newIntegrationEngine(t)
	creator := newIntegrationCreator(t, engine)

	rule := armotypes.RuntimeRule{
		ID:          "R2000",
		Name:        "Exec to pod",
		Description: "Detect exec to pod via admission webhook",
		Severity:    armotypes.RuleSeverityLow,
		Expressions: armotypes.RuleExpressions{
			Message:  `"Exec to pod: " + event.Name + " by " + event.UserInfo.Username`,
			UniqueID: `event.Namespace + "/" + event.Name`,
			RuleExpression: []armotypes.RuleExpression{
				{EventType: admissioncel.EventTypeK8sAdmission, Expression: `event.Kind == "PodExecOptions"`},
			},
		},
	}
	creator.SyncRules([]armotypes.RuntimeRule{rule})

	evaluator := creator.CreateRuleByID("R2000")
	require.NotNil(t, evaluator, "expected non-nil evaluator for R2000")

	attrs := buildAttrs(
		"PodExecOptions",
		"web-server",
		"production",
		"exec",
		admission.Connect,
		map[string]interface{}{
			"command":   []interface{}{"/bin/bash"},
			"container": "app",
		},
		"developer@example.com",
	)

	failure := evaluator.ProcessEvent(attrs, nil)

	require.NotNil(t, failure, "expected RuleFailure, got nil")
	assert.Equal(t, "R2000", failure.GetRuleId())

	base := failure.GetBaseRuntimeAlert()
	assert.Equal(t, "Exec to pod: web-server by developer@example.com", base.AlertName)
	assert.Equal(t, armotypes.RuleSeverityLow, base.Severity)
	assert.Equal(t, "production/web-server", base.UniqueID)
	assert.False(t, base.Timestamp.IsZero(), "Timestamp must not be zero")

	ruleAlert := failure.GetRuleAlert()
	assert.Equal(t, "Detect exec to pod via admission webhook", ruleAlert.RuleDescription)

	admAlert := failure.GetAdmissionsAlert()
	assert.Equal(t, "web-server", admAlert.ObjectName)
	assert.Equal(t, "production", admAlert.RequestNamespace)
	assert.Equal(t, "exec", admAlert.Subresource)
	assert.Equal(t, "PodExecOptions", admAlert.Kind.Kind)
	assert.Equal(t, admission.Connect, admAlert.Operation)
	require.NotNil(t, admAlert.UserInfo, "AdmissionAlert.UserInfo must not be nil")
	assert.Equal(t, "developer@example.com", admAlert.UserInfo.Name)
}

// TestIntegration_PortForward_CELRule validates the full pipeline for a PodPortForwardOptions event.
func TestIntegration_PortForward_CELRule(t *testing.T) {
	engine := newIntegrationEngine(t)
	creator := newIntegrationCreator(t, engine)

	rule := armotypes.RuntimeRule{
		ID:          "R2001",
		Name:        "Port forward to pod",
		Description: "Detect port-forward to pod via admission webhook",
		Severity:    armotypes.RuleSeverityLow,
		Expressions: armotypes.RuleExpressions{
			Message:  `"Port forward to pod: " + event.Name`,
			UniqueID: `event.Namespace + "/" + event.Name`,
			RuleExpression: []armotypes.RuleExpression{
				{EventType: admissioncel.EventTypeK8sAdmission, Expression: `event.Kind == "PodPortForwardOptions"`},
			},
		},
	}
	creator.SyncRules([]armotypes.RuntimeRule{rule})

	evaluator := creator.CreateRuleByID("R2001")
	require.NotNil(t, evaluator, "expected non-nil evaluator for R2001")

	attrs := buildAttrs(
		"PodPortForwardOptions",
		"db-pod",
		"staging",
		"portforward",
		admission.Connect,
		map[string]interface{}{
			"ports": []interface{}{5432},
		},
		"ops@example.com",
	)

	failure := evaluator.ProcessEvent(attrs, nil)

	require.NotNil(t, failure, "expected RuleFailure, got nil")
	assert.Equal(t, "R2001", failure.GetRuleId())

	base := failure.GetBaseRuntimeAlert()
	assert.Equal(t, "Port forward to pod: db-pod", base.AlertName)
	assert.Equal(t, armotypes.RuleSeverityLow, base.Severity)
	assert.Equal(t, "staging/db-pod", base.UniqueID)
	assert.False(t, base.Timestamp.IsZero(), "Timestamp must not be zero")

	admAlert := failure.GetAdmissionsAlert()
	assert.Equal(t, "PodPortForwardOptions", admAlert.Kind.Kind)
	assert.Equal(t, "db-pod", admAlert.ObjectName)
	assert.Equal(t, "staging", admAlert.RequestNamespace)
}

// TestIntegration_NoMatch_DifferentKind ensures no failure is returned when the
// event kind does not match the rule's expression.
func TestIntegration_NoMatch_DifferentKind(t *testing.T) {
	engine := newIntegrationEngine(t)
	creator := newIntegrationCreator(t, engine)

	// Rule only fires on PodExecOptions.
	rule := armotypes.RuntimeRule{
		ID:       "R2000",
		Name:     "Exec to pod",
		Severity: armotypes.RuleSeverityLow,
		Expressions: armotypes.RuleExpressions{
			RuleExpression: []armotypes.RuleExpression{
				{EventType: admissioncel.EventTypeK8sAdmission, Expression: `event.Kind == "PodExecOptions"`},
			},
		},
	}
	creator.SyncRules([]armotypes.RuntimeRule{rule})

	evaluator := creator.CreateRuleByID("R2000")
	require.NotNil(t, evaluator)

	// Build a Deployment CREATE event — completely different kind.
	gvk := schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}
	gvr := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata":   map[string]interface{}{"name": "my-deploy", "namespace": "default"},
	}}
	userInfo := &user.DefaultInfo{Name: "admin"}
	attrs := admission.NewAttributesRecord(obj, nil, gvk, "default", "my-deploy", gvr, "",
		admission.Create, nil, false, userInfo)

	failure := evaluator.ProcessEvent(attrs, nil)
	assert.Nil(t, failure, "expected nil failure for non-matching Deployment CREATE event")
}

// TestIntegration_GenericAdmissionRule demonstrates that the CEL engine works for
// arbitrary admission events beyond exec/portforward.
func TestIntegration_GenericAdmissionRule(t *testing.T) {
	engine := newIntegrationEngine(t)
	creator := newIntegrationCreator(t, engine)

	rule := armotypes.RuntimeRule{
		ID:          "R2002",
		Name:        "Pod created",
		Description: "Detect any Pod creation event",
		Severity:    armotypes.RuleSeverityLow,
		Expressions: armotypes.RuleExpressions{
			Message:  `"Pod created: " + event.Namespace + "/" + event.Name`,
			UniqueID: `event.Namespace + "/" + event.Name`,
			RuleExpression: []armotypes.RuleExpression{
				{
					EventType:  admissioncel.EventTypeK8sAdmission,
					Expression: `event.Operation == "CREATE" && event.Kind == "Pod"`,
				},
			},
		},
	}
	creator.SyncRules([]armotypes.RuntimeRule{rule})

	evaluator := creator.CreateRuleByID("R2002")
	require.NotNil(t, evaluator, "expected non-nil evaluator for R2002")

	attrs := buildAttrs(
		"Pod",
		"my-app",
		"default",
		"",
		admission.Create,
		map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata":   map[string]interface{}{"name": "my-app", "namespace": "default"},
		},
		"ci-bot@example.com",
	)

	failure := evaluator.ProcessEvent(attrs, nil)

	require.NotNil(t, failure, "expected RuleFailure for Pod CREATE event")
	assert.Equal(t, "R2002", failure.GetRuleId())

	base := failure.GetBaseRuntimeAlert()
	assert.Equal(t, "Pod created: default/my-app", base.AlertName)
	assert.Equal(t, armotypes.RuleSeverityLow, base.Severity)
	assert.Equal(t, "default/my-app", base.UniqueID)

	admAlert := failure.GetAdmissionsAlert()
	assert.Equal(t, "Pod", admAlert.Kind.Kind)
	assert.Equal(t, "my-app", admAlert.ObjectName)
	assert.Equal(t, "default", admAlert.RequestNamespace)
	assert.Equal(t, admission.Create, admAlert.Operation)

	// Ensure the same rule does NOT fire for a Deployment create.
	attrsDeployment := buildAttrs(
		"Deployment",
		"my-deploy",
		"default",
		"",
		admission.Create,
		map[string]interface{}{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
		},
		"ci-bot@example.com",
	)
	noFailure := evaluator.ProcessEvent(attrsDeployment, nil)
	assert.Nil(t, noFailure, "rule R2002 must not fire for Deployment CREATE")
}
